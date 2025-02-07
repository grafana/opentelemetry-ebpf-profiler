package table

import (
	"encoding/binary"
	"fmt"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/ebpf-profiler/pyroscope/symb/ffi"
	"golang.org/x/sys/unix"
	"io"
	"math"
	"os"
	"runtime"
	"sort"
	"unsafe"
)

const (
	magic   uint32 = 0x6c627467 // "gtbl"
	version uint32 = 1
)

type header struct {
	magic         uint32
	version       uint32
	rangesOffset  uint64
	stringsOffset uint64
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
type Table struct {
	file         *os.File
	rangesOffset uint64
	rangesCount  uint64
	strOff       uint64

	rangesHot []entry
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
	if _, err := res.file.Read(headerBuf); err != nil {
		res.Close()
		return nil, err
	}

	hdr := (*header)(unsafe.Pointer(&headerBuf[0]))

	if hdr.magic != magic {
		res.Close()
		return nil, fmt.Errorf("invalid magic number")
	}
	if hdr.version != version {
		res.Close()
		return nil, fmt.Errorf("unsupported version")
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
	//for _, e := range res.ranges {
	//	fmt.Printf("        range %8x %8x %s\n", e.va, e.length, res.extractFuncName(e.fun))
	//}
	return res, nil
}

func (st *Table) getEntry(i int) (entry, error) {
	if i < 0 || uint64(i) >= st.rangesCount {
		return entry{}, fmt.Errorf("index out of bounds")
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
		st.file = nil
		return
	}
	return
}

func (st *Table) func_(offset uint32) string {
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

func (st *Table) Lookup(addr64 uint64, result []string) []string {
	//result = st.lookupHot(addr64, result)
	//if len(result) > 0 {
	//	return result
	//}
	return st.lookupCold(addr64, result)
}

func (st *Table) lookupCold(addr64 uint64, result []string) []string {
	result = result[:0]
	if addr64 >= math.MaxUint32 {
		return result
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
		return result
	}
	idx--
	for idx >= 0 {
		it, err := st.getEntry(idx)
		if err != nil {
			return result[:0]
		}

		covered := it.va <= addr && addr < it.va+it.length
		if covered {
			name := st.func_(it.fun)
			result = append(result, name)
		}
		if it.depth == 0 {
			break
		}
		idx--
	}
	return result
}

func (st *Table) lookupHot(addr64 uint64, result []string) []string {
	result = result[:0]
	if len(st.rangesHot) == 0 {
		return result
	}
	if addr64 >= math.MaxUint32 {
		return result
	}
	addr := uint32(addr64)
	idx := sort.Search(len(st.rangesHot), func(i int) bool {
		return st.rangesHot[i].va > addr
	})
	idx--
	for idx >= 0 {
		it := st.rangesHot[idx]
		covered := it.va <= addr && addr < it.va+it.length
		if covered {
			name := st.func_(it.fun)
			result = append(result, name)
		}
		if it.depth == 0 {
			break
		}
		idx--
	}
	return result
}

func (st *Table) Size() int {
	return 0
}

func (st *Table) String() string {
	return fmt.Sprintf("ranges: %d", st.rangesCount)
}

func FDToTable(executable *os.File, dwarfSup *os.File, output *os.File) error {
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
	log.Debugf("converted %s -> %s : %d ranges, %d strings", executable.Name(), output.Name(), len(rb.entries), len(sb.unique))

	return nil
}
