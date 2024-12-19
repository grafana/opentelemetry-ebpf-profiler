package symb

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"sort"
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
		return 0, fmt.Errorf("string offset overflow")
	}

	strLen := len(s)
	if strLen >= int(^uint32(0)) {
		return 0, fmt.Errorf("string length overflow")
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
	entry := entry{
		va:     va,
		length: length,
		depth:  depth,
		fun:    funcID,
	}
	rb.entries = append(rb.entries, entry)
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

func (rc *rangeCollector) VisitRange(va uint64, length uint32, depth uint32, function string) {
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
	header := header{
		magic:   magic,
		version: version,
	}
	headerBytes := make([]byte, 16)
	binary.LittleEndian.PutUint32(headerBytes[0:], header.magic)
	binary.LittleEndian.PutUint32(headerBytes[4:], header.version)
	if err := writeAligned(output, headerBytes); err != nil {
		return err
	}

	rangesOffset, err := output.Seek(0, os.SEEK_CUR)
	if err != nil {
		return err
	}

	for _, entry := range rb.entries {
		entryBytes := make([]byte, 16)
		binary.LittleEndian.PutUint32(entryBytes[0:], entry.va)
		binary.LittleEndian.PutUint32(entryBytes[4:], entry.length)
		binary.LittleEndian.PutUint32(entryBytes[8:], entry.depth)
		binary.LittleEndian.PutUint32(entryBytes[12:], entry.fun)
		if err := writeAligned(output, entryBytes); err != nil {
			return err
		}
	}

	stringsOffset, err := output.Seek(0, os.SEEK_CUR)
	if err != nil {
		return err
	}

	if err := writeAligned(output, sb.buf); err != nil {
		return err
	}

	header.rangesOffset = uint64(rangesOffset)
	header.stringsOffset = uint64(stringsOffset)

	if _, err := output.Seek(0, os.SEEK_SET); err != nil {
		return err
	}

	headerBytes = make([]byte, 32)
	binary.LittleEndian.PutUint32(headerBytes[0:], header.magic)
	binary.LittleEndian.PutUint32(headerBytes[4:], header.version)
	binary.LittleEndian.PutUint64(headerBytes[8:], header.rangesOffset)
	binary.LittleEndian.PutUint64(headerBytes[16:], header.stringsOffset)

	if _, err := output.Write(headerBytes); err != nil {
		return err
	}

	if _, err := output.Seek(0, io.SeekStart); err != nil {
		return err
	}
	return nil
}
