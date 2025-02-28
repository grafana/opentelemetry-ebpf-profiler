package table

import (
	"encoding/binary"
	"sort"
)

type stringBuilder struct {
	buf      []byte
	unique   map[string]uint64
	offset   uint64
	overflow uint64
	emptystr uint64
}

func newStringBuilder() *stringBuilder {
	sb := &stringBuilder{
		buf:    make([]byte, 0),
		unique: make(map[string]uint64),
	}
	sb.emptystr = sb.add("")
	sb.overflow = sb.add("[overflow]")
	return sb
}

func (sb *stringBuilder) add(s string) uint64 {
	if prev, exists := sb.unique[s]; exists {
		return prev
	}

	strLen := len(s)
	if strLen >= int(^uint32(0)) {
		return sb.overflow
	}
	sb.buf = binary.LittleEndian.AppendUint32(sb.buf, uint32(strLen))
	sb.buf = append(sb.buf, s...)

	offset := sb.offset
	sb.unique[s] = offset
	sb.offset += uint64(4 + strLen)

	return offset
}

type rangesBuilder struct {
	entries []rangeEntry
	va      []uint64
}

func newRangesBuilder() *rangesBuilder {
	return &rangesBuilder{}
}

func (rb *rangesBuilder) add(va, length, depth, funcOffset, fileOffset uint64) {
	e := rangeEntry{
		length:     length,
		depth:      depth,
		funcOffset: funcOffset,
		fileOffset: fileOffset,
	}
	rb.entries = append(rb.entries, e)
	rb.va = append(rb.va, va)
}

type sortByVADepth struct {
	b *rangesBuilder
}

func (s *sortByVADepth) Len() int {
	return len(s.b.entries)
}

func (s *sortByVADepth) Less(i, j int) bool {
	if s.b.va[i] == s.b.va[j] {
		return s.b.entries[i].depth < s.b.entries[j].depth
	}
	return s.b.va[i] < s.b.va[j]
}

func (s *sortByVADepth) Swap(i, j int) {
	s.b.entries[i], s.b.entries[j] = s.b.entries[j], s.b.entries[i]
	s.b.va[i], s.b.va[j] = s.b.va[j], s.b.va[i]
}

func (rb *rangesBuilder) sort() {
	sort.Sort(&sortByVADepth{rb})
}

type rangeCollector struct {
	sb *stringBuilder
	rb *rangesBuilder

	opt options
}

func (rc *rangeCollector) VisitRange(va, length uint64, depth uint32, function, file string) {
	funcOffset := rc.sb.add(function)
	fileOffset := rc.sb.emptystr
	if rc.opt.files {
		fileOffset = rc.sb.add(file)
	}
	//todo line
	rc.rb.add(va, length, uint64(depth), funcOffset, fileOffset)
}
