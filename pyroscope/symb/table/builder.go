package table

import (
	"encoding/binary"
	"errors"
	"io"
	"os"
	"sort"
	"unsafe"
)

type stringBuilder struct {
	buf    []byte
	unique map[string]uint32
	offset uint64
}

func newStringBuilder() *stringBuilder {
	return &stringBuilder{
		buf:    make([]byte, 0),
		unique: make(map[string]uint32),
	}
}

func (sb *stringBuilder) add(s string) (uint32, error) {
	if id, exists := sb.unique[s]; exists {
		return id, nil
	}

	if sb.offset >= uint64(^uint32(0)) {
		return 0, errors.New("string offset overflow")
	}

	strLen := len(s)
	if strLen >= int(^uint32(0)) {
		return 0, errors.New("string length overflow")
	}

	lenBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(lenBytes, uint32(strLen))

	sb.buf = append(sb.buf, lenBytes...)
	sb.buf = append(sb.buf, []byte(s)...)

	offset := uint32(sb.offset)
	sb.unique[s] = offset
	sb.offset += uint64(4 + strLen)

	return offset, nil
}

type rangesBuilder struct {
	entries []entry
}

func newRangesBuilder() *rangesBuilder {
	return &rangesBuilder{
		entries: make([]entry, 0),
	}
}

func (rb *rangesBuilder) add(va, length, depth, funcID uint32) {
	e := entry{
		va:     va,
		length: length,
		depth:  depth,
		fun:    funcID,
	}
	rb.entries = append(rb.entries, e)
}

func (rb *rangesBuilder) sort() {
	sort.Slice(rb.entries, func(i, j int) bool {
		if rb.entries[i].va == rb.entries[j].va {
			return rb.entries[i].depth < rb.entries[j].depth
		}
		return rb.entries[i].va < rb.entries[j].va
	})
}

type rangeCollector struct {
	sb *stringBuilder
	rb *rangesBuilder
}

func (rc *rangeCollector) VisitRange(va uint64, length, depth uint32, function string) {
	if va >= uint64(^uint32(0)) {
		return // Skip if VA doesn't fit in uint32
	}

	funcID, err := rc.sb.add(function)
	if err != nil {
		return // Skip on error
	}

	rc.rb.add(uint32(va), length, depth, funcID)
}

func write(output *os.File, rc *rangeCollector) error {
	rb := rc.rb
	sb := rc.sb
	hdr := &header{
		magic:   magic,
		version: version,
	}
	headerBuf := unsafe.Slice((*byte)(unsafe.Pointer(hdr)), int(unsafe.Sizeof(*hdr)))
	if _, err := output.Write(headerBuf); err != nil {
		return err
	}

	rangesOffset, err := output.Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}

	for _, entry := range rb.entries {
		entryBytes := make([]byte, 16)
		binary.LittleEndian.PutUint32(entryBytes[0:], entry.va)
		binary.LittleEndian.PutUint32(entryBytes[4:], entry.length)
		binary.LittleEndian.PutUint32(entryBytes[8:], entry.depth)
		binary.LittleEndian.PutUint32(entryBytes[12:], entry.fun)
		if _, err = output.Write(entryBytes); err != nil {
			return err
		}
	}

	stringsOffset, err := output.Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}

	if _, err = output.Write(sb.buf); err != nil {
		return err
	}

	hdr.rangesOffset = uint64(rangesOffset)
	hdr.stringsOffset = uint64(stringsOffset)

	if _, err = output.Seek(0, io.SeekStart); err != nil {
		return err
	}

	if _, err = output.Write(headerBuf); err != nil {
		return err
	}

	if _, err = output.Seek(0, io.SeekStart); err != nil {
		return err
	}
	return nil
}
