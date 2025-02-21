package table

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"sort"

	"golang.org/x/sys/unix"
)

const (
	magic   uint32 = 0x6c627467 // "gtbl"
	version uint32 = 1
)

var (
	versionName = fmt.Sprintf("gtbl-%d", version)
)

func VersionName() string {
	return versionName
}

type entry struct {
	va uint64
	rangeEntry
}

func (e entry) String() string {
	return fmt.Sprintf("va: %x, length: %d, depth: %d, fun: %d", e.va, e.length, e.depth, e.funcOffset)
}

// todo store line table
// todo fix libc readelf test
// todo: prefetch multiple entries to minimize io calls
type Table struct {
	file *os.File
	hdr  header
	opt  options

	vaTable []byte

	fieldsBuffer []byte
}
type Option func(*options)

func WithCRC() Option {
	return func(o *options) {
		o.crc = true
	}
}

func WithLines() Option {
	return func(o *options) {
		o.lines = true
	}
}

func WithFiles() Option {
	return func(o *options) {
		o.files = true
	}
}

type options struct {
	crc   bool
	lines bool
	files bool
}

func OpenPath(path string, opt ...Option) (*Table, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	return OpenFile(f, opt...)
}

func OpenFile(f *os.File, opt ...Option) (*Table, error) {
	var err error
	res := new(Table)

	for _, o := range opt {
		o(&res.opt)
	}

	res.file = f

	hdr, err := readHeader(f)
	if err != nil {
		res.Close()
		return nil, err
	}

	if hdr.magic != magic {
		res.Close()
		return nil, errors.New("invalid magic number")
	}
	if hdr.version != version {
		res.Close()
		return nil, errors.New("unsupported version")
	}
	if hdr.vaTableHeader.entrySize != 4 && hdr.vaTableHeader.entrySize != 8 {
		res.Close()
		return nil, errors.New("invalid vaSize")
	}
	if hdr.rangeTableHeader.fieldSize != 4 && hdr.rangeTableHeader.fieldSize != 8 {
		res.Close()
		return nil, errors.New("invalid fieldSize")
	}
	if hdr.rangeTableHeader.count != hdr.vaTableHeader.count {
		res.Close()
		return nil, errors.New("invalid count")
	}
	res.hdr = hdr

	res.fieldsBuffer = make([]byte, int(hdr.rangeTableHeader.fieldSize)*fieldsCount)
	res.vaTable = make([]byte, int(hdr.vaTableHeader.entrySize)*int(hdr.vaTableHeader.count))

	if _, err = f.ReadAt(res.vaTable, int64(hdr.vaTableHeader.offset)); err != nil {
		res.Close()
		return nil, err
	}
	if res.opt.crc {
		if err = res.CheckCRC(); err != nil {
			res.Close()
			return nil, err
		}
	}

	err = unix.Fadvise(int(res.file.Fd()), 0, 0, unix.FADV_RANDOM)
	if err != nil {
		fmt.Printf("failed to Fadvise: %s\n", err)
	}

	return res, nil
}

func (st *Table) getEntryVA(i int) uint64 {
	offset := int64(i) * int64(st.hdr.vaTableHeader.entrySize)
	it := st.vaTable[offset : offset+int64(st.hdr.vaTableHeader.entrySize)]
	if st.hdr.vaTableHeader.entrySize == 4 {
		return uint64(binary.LittleEndian.Uint32(it))
	}
	return binary.LittleEndian.Uint64(it)
}

func (st *Table) getEntry(i int) (entry, error) {
	if i < 0 || i >= int(st.hdr.vaTableHeader.count) {
		return entry{}, errors.New("index out of bounds")
	}
	offset := int64(st.hdr.rangeTableHeader.offset) + int64(i)*int64(len(st.fieldsBuffer))

	if _, err := st.file.ReadAt(st.fieldsBuffer, offset); err != nil {
		return entry{}, err
	}
	e := entry{}
	if st.hdr.rangeTableHeader.fieldSize == 4 {
		e.rangeEntry = readFields4(st.fieldsBuffer)
	} else {
		e.rangeEntry = readFields8(st.fieldsBuffer)
	}
	e.va = st.getEntryVA(i)
	return e, nil
}

func (st *Table) Close() {
	if st.file != nil {
		_ = st.file.Close()
	}
}

func (st *Table) str(offset uint64) string {
	if offset == 0 {
		return ""
	}
	var strLen uint32
	buf := st.fieldsBuffer[:4]

	if _, err := st.file.ReadAt(buf, int64(st.hdr.stringsTableHeader.offset+offset)); err != nil {
		return ""
	}
	strLen = binary.LittleEndian.Uint32(buf)
	strData := make([]byte, strLen)
	if _, err := st.file.ReadAt(strData, int64(st.hdr.stringsTableHeader.offset+offset+4)); err != nil {
		if err != io.EOF {
			return ""
		}
	}
	return string(strData)
}

type LookupResult struct {
	Name string
	File string
	Line int
}

func (st *Table) Lookup(addr64 uint64) ([]LookupResult, error) {
	var result []LookupResult

	addr := addr64
	idx := sort.Search(int(st.hdr.vaTableHeader.count), func(i int) bool {
		return st.getEntryVA(i) > addr
	})
	idx--
	for idx >= 0 {
		it, err := st.getEntry(idx) // todo: prefetch multiple entries to minimize io calls
		if err != nil {
			return result[:0], err
		}

		covered := it.va <= addr && addr < it.va+it.length
		if covered {
			name := st.str(it.funcOffset)
			res := LookupResult{
				Name: name,
			}
			if st.opt.files {
				res.File = st.str(it.fileOffset)
			}
			//todo line
			result = append(result, res)
		}
		if it.depth == 0 {
			break
		}
		idx--
	}
	return result, nil
}

func (st *Table) String() string {
	return fmt.Sprintf("ranges: %+v", st.hdr)
}

func (st *Table) Count() int {
	return int(st.hdr.vaTableHeader.count)
}

func (st *Table) CheckCRC() error {
	if err := st.CheckCRCVA(); err != nil {
		return err
	}
	if err := st.CheckCRCStrings(); err != nil {
		return err
	}
	if err := st.CheckCRCFields(); err != nil {
		return err
	}
	return nil
}

func (st *Table) CheckCRCVA() error {
	crc := crc32.New(castagnoli)
	_, _ = crc.Write(st.vaTable)
	if crc.Sum32() != st.hdr.vaTableHeader.crc {
		return errors.New("crc mismatch in va table")
	}
	return nil
}

func (st *Table) CheckCRCStrings() error {
	crc := crc32.New(castagnoli)
	_, _ = io.Copy(crc, io.NewSectionReader(st.file, int64(st.hdr.stringsTableHeader.offset), int64(st.hdr.stringsTableHeader.size)))
	if crc.Sum32() != st.hdr.stringsTableHeader.crc {
		return errors.New("crc mismatch in strings table")
	}
	return nil
}

func (st *Table) CheckCRCFields() error {
	crc := crc32.New(castagnoli)
	sz := int64(st.hdr.rangeTableHeader.fieldSize) * fieldsCount * int64(st.hdr.rangeTableHeader.count)
	_, _ = io.Copy(crc, io.NewSectionReader(st.file, int64(st.hdr.rangeTableHeader.offset), sz))
	if crc.Sum32() != st.hdr.rangeTableHeader.crc {
		return errors.New("crc mismatch in fields table")
	}
	return nil
}
