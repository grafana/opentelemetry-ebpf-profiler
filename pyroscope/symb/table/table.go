package table

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"runtime"
	"sort"
	"unsafe"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/ebpf-profiler/pyroscope/symb/ffi"
	"golang.org/x/sys/unix"
)

const (
	magic   uint32 = 0x6c627467 // "gtbl"
	version uint32 = 1
)

var (
	versionName = fmt.Sprintf("table-%d", version)
)

func VersionName() string {
	return versionName
}

type header struct {
	magic         uint32
	version       uint32
	rangesOffset  uint64
	stringsOffset uint64
	padding       uint64
}

type entry struct {
	va     uint32
	length uint32
	depth  uint32
	fun    uint32
}

func (e entry) String() string {
	return fmt.Sprintf("va: %x, length: %d, depth: %d, fun: %d", e.va, e.length, e.depth, e.fun)
}

// todo add 64bit support
// todo change the layout of the file, separate tables for addresses and the rest of entry fields ?
type Table struct {
	file         *os.File
	rangesOffset uint64
	rangesCount  uint64
	strOff       uint64
}

func OpenPath(path string) (*Table, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	return OpenFile(f)
}

func OpenFile(f *os.File) (*Table, error) {
	var err error
	res := new(Table)

	res.file = f

	headerBuf := make([]byte, unsafe.Sizeof(header{}))
	if _, readErr := res.file.Read(headerBuf); readErr != nil {
		res.Close()
		return nil, readErr
	}

	hdr := (*header)(unsafe.Pointer(&headerBuf[0]))

	if hdr.magic != magic {
		res.Close()
		return nil, errors.New("invalid magic number")
	}
	if hdr.version != version {
		res.Close()
		return nil, errors.New("unsupported version")
	}

	res.rangesOffset = hdr.rangesOffset
	res.rangesCount = (hdr.stringsOffset - hdr.rangesOffset) / 16 // each entry is 16 bytes
	res.strOff = hdr.stringsOffset

	err = unix.Fadvise(int(res.file.Fd()), 0, 0, unix.FADV_RANDOM)
	if err != nil {
		fmt.Printf("failed to Fadvise: %s\n", err)
	}

	runtime.SetFinalizer(res, func(r *Table) {
		if r.file != nil {
			fmt.Printf("WARNING: unclosed file %s\n", res.file.Name())
			r.file.Close()
		}
	})
	return res, nil
}

func (st *Table) getEntry(i int) (entry, error) {
	if i < 0 || uint64(i) >= st.rangesCount {
		return entry{}, errors.New("index out of bounds")
	}

	entrySize := int64(unsafe.Sizeof(entry{}))
	offset := int64(st.rangesOffset) + int64(i)*entrySize

	buf := make([]byte, entrySize)
	_, err := st.file.ReadAt(buf, offset)
	if err != nil {
		return entry{}, err
	}

	return *(*entry)(unsafe.Pointer(&buf[0])), nil
}

func (st *Table) Close() {
	if st.file != nil {
		_ = st.file.Close()
	}
}

func (st *Table) function(offset uint32) string {
	var strLen uint32
	buf := make([]byte, 4)
	if _, err := st.file.ReadAt(buf, int64(st.strOff+uint64(offset))); err != nil {
		return ""
	}
	strLen = binary.LittleEndian.Uint32(buf)

	strData := make([]byte, strLen)
	if _, err := st.file.ReadAt(strData, int64(st.strOff+uint64(offset)+4)); err != nil {
		if err != io.EOF {
			return ""
		}
	}
	return string(strData)
}

func (st *Table) Lookup(addr64 uint64) ([]string, error) {
	var result []string
	if addr64 >= math.MaxUint32 {
		return result, errors.New("table address out of bounds")
	}
	addr := uint32(addr64)
	var err error
	idx := sort.Search(int(st.rangesCount), func(i int) bool {
		e, itErr := st.getEntry(i)
		if itErr != nil {
			err = itErr
			return true
		}
		return e.va > addr
	})
	if err != nil {
		return result, err
	}
	idx--
	for idx >= 0 {
		it, err := st.getEntry(idx) // todo: prefetch multiple entries to minimize io calls
		if err != nil {
			return result[:0], err
		}

		covered := it.va <= addr && addr < it.va+it.length
		if covered {
			name := st.function(it.fun)
			result = append(result, name)
		}
		if it.depth == 0 {
			break
		}
		idx--
	}
	return result, nil
}

func (st *Table) Size() int {
	return 0
}

func (st *Table) String() string {
	return fmt.Sprintf("ranges: %d", st.rangesCount)
}

func FDToTable(executable, output *os.File) error {
	sb := newStringBuilder()
	rb := newRangesBuilder()
	rc := &rangeCollector{sb: sb, rb: rb}

	if err := ffi.RangeExtractor(executable, rc); err != nil {
		return err
	}
	rb.sort()

	err2 := write(output, rc)
	if err2 != nil {
		return err2
	}
	log.Debugf("converted %s -> %s : %d ranges, %d strings",
		executable.Name(),
		output.Name(),
		len(rb.entries),
		len(sb.unique))

	return nil
}
