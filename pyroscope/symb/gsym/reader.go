package gsym

// https://raw.githubusercontent.com/ChimeHQ/gogsym/refs/heads/main/gsym.go

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	bufra "github.com/avvmoto/buf-readerat"
	"github.com/chimehq/binarycursor"
)

const Magic uint32 = 0x4753594d
const Cigam uint32 = 0x4d595347
const Version = 1
const MaxUUIDSize = 20
const HeaderSize = 28 + MaxUUIDSize

var ErrUnsupportedVersion = errors.New("unsupported Version")
var ErrAddressOutOfRange = errors.New("address out of range")
var ErrUUIDSizeOutOfRange = errors.New("UUID size out of range")
var ErrAddressSizeOutOfrange = errors.New("address size out of range")
var ErrAddressNotFound = errors.New("address not found")

type Header struct {
	Magic        uint32
	Version      uint16
	AddrOffSize  uint8
	UUIDSize     uint8
	BaseAddress  uint64
	NumAddresses uint32
	StrtabOffset uint32
	StrtabSize   uint32
	UUID         [MaxUUIDSize]byte
}

func (h Header) Size() int64 {
	return int64(HeaderSize)
}

func newHeader(bc binarycursor.BinaryCursor) (Header, error) {
	h := Header{}

	var err error

	h.Magic, err = bc.ReadUint32()
	if err != nil {
		return h, err
	}

	if h.Magic == Cigam {
		bc.FlipOrder()
	} else if h.Magic != Magic {
		return h, fmt.Errorf("invalid magic: %x", h.Magic)
	}

	h.Version, err = bc.ReadUint16()
	if err != nil {
		return h, err
	}

	if h.Version != uint16(1) {
		return h, ErrUnsupportedVersion
	}

	h.AddrOffSize, err = bc.ReadUint8()
	if err != nil {
		return h, err
	}

	h.UUIDSize, err = bc.ReadUint8()
	if err != nil {
		return h, err
	}

	if h.UUIDSize > MaxUUIDSize {
		return h, ErrUUIDSizeOutOfRange
	}

	h.BaseAddress, err = bc.ReadUint64()
	if err != nil {
		return h, err
	}

	h.NumAddresses, err = bc.ReadUint32()
	if err != nil {
		return h, err
	}

	h.StrtabOffset, err = bc.ReadUint32()
	if err != nil {
		return h, err
	}

	h.StrtabSize, err = bc.ReadUint32()
	if err != nil {
		return h, err
	}

	n, _ := bc.Read(h.UUID[0:h.UUIDSize])
	if n != int(h.UUIDSize) {
		return h, fmt.Errorf("expected %d UUIDS bytes, got %d", h.UUIDSize, n)
	}

	return h, nil
}

func (h Header) UUIDBytes() []byte {
	return h.UUID[0:h.UUIDSize]
}

func (h Header) UUIDString() string {
	return hex.EncodeToString(h.UUIDBytes())
}

type Gsym struct {
	readerAt  *os.File
	cursor    binarycursor.BinaryCursor
	Header    Header
	addresses []byte

	buf [512]byte
}

func (g *Gsym) Lookup(addr uint64) ([]string, error) {
	res, err := g.LookupAddress(addr)
	if err != nil {
		return nil, err
	}
	symbols := make([]string, 0, len(res.Locations))
	for _, location := range res.Locations {
		symbols = append(symbols, location.Name)
	}
	return symbols, nil
}

const readAddresses = true

func NewGsymWithReader(r *os.File) (*Gsym, error) {
	bc := binarycursor.NewBinaryReaderAtCursor(r, 0)

	g := &Gsym{
		readerAt: r,
		cursor:   bc,
		Header:   Header{},
	}

	header, err := newHeader(bc)
	if err != nil {
		return g, err
	}
	g.Header = header
	if readAddresses {
		sz := int64(header.NumAddresses) * int64(header.AddrOffSize)
		addresses := make([]byte, sz)
		_, err = r.ReadAt(addresses, g.AddressTableOffset())
		if err != nil {
			return g, err
		}
		g.addresses = addresses
	}

	return g, nil
}

func (g *Gsym) cursorAt(offset int64) binarycursor.BinaryCursor {
	c := binarycursor.NewBinaryReaderAtCursor(g.readerAt, offset)

	c.SetOrder(g.cursor.Order())

	return c
}

func (g *Gsym) bufferedCursorAt(offset int64) binarycursor.BinaryCursor {
	bufstr := bufra.NewBufReaderAt(g.readerAt, 512)
	c := binarycursor.NewBinaryReaderAtCursor(bufstr, offset)

	c.SetOrder(g.cursor.Order())

	return c
}

func (g *Gsym) AddressTableOffset() int64 {
	return g.Header.Size()
}

func (g *Gsym) ReadAddressEntry(idx int) (uint64, error) {
	if g.addresses != nil {
		entry := g.addresses[idx*int(g.Header.AddrOffSize) : (idx+1)*int(g.Header.AddrOffSize)]
		switch g.Header.AddrOffSize {
		case 1:
			v8 := entry[0]
			return uint64(v8), nil
		case 2:
			v16 := g.cursor.Order().Uint16(entry)
			return uint64(v16), nil
		case 4:
			v32 := g.cursor.Order().Uint32(entry)

			return uint64(v32), nil
		case 8:
			v64 := g.cursor.Order().Uint64(entry)
			return v64, nil
		}
	}
	offset := int64(idx)*int64(g.Header.AddrOffSize) + g.AddressTableOffset()
	cursor := g.cursorAt(offset)

	switch g.Header.AddrOffSize {
	case 1:
		v8, err := cursor.ReadUint8()

		return uint64(v8), err
	case 2:
		v16, err := cursor.ReadUint16()

		return uint64(v16), err
	case 4:
		v32, err := cursor.ReadUint32()

		return uint64(v32), err
	case 8:
		return cursor.ReadUint64()
	}

	return uint64(0), ErrAddressSizeOutOfrange
}

func (g *Gsym) GetTextRelativeAddressIndex(addr uint64) (int, error) {
	return g.GetAddressIndex(addr + g.Header.BaseAddress)
}

func (g *Gsym) GetAddressIndex(addr uint64) (int, error) {
	if addr < g.Header.BaseAddress {
		return 0, ErrAddressOutOfRange
	}

	relAddr := addr - g.Header.BaseAddress
	count := int(g.Header.NumAddresses)

	idx := sort.Search(count, func(i int) bool {
		entryAddr, _ := g.ReadAddressEntry(i)

		return entryAddr > relAddr
	})
	idx--
	if idx < 0 {
		return 0, ErrAddressNotFound
	}
	return idx, nil
}

func (g *Gsym) AddressInfoTableOffset() int64 {
	addrTableSize := int64(g.Header.NumAddresses) * int64(g.Header.AddrOffSize)

	return g.AddressTableOffset() + addrTableSize
}

func (g *Gsym) GetAddressInfoOffset(index int) (int64, error) {
	offset := g.AddressInfoTableOffset() + int64(index*4)

	c := g.cursorAt(offset)

	value, err := c.ReadUint32()

	return int64(value), err
}

func (g *Gsym) GetString(offset int64) (string, error) {
	strOffset := int64(g.Header.StrtabOffset) + offset
	const manualStringRead = true

	if manualStringRead {
		sb := strings.Builder{}
		buf := g.buf[:]
		for {
			n, err := g.readerAt.ReadAt(buf, strOffset)

			null := bytes.IndexByte(buf, 0)
			if null != -1 {
				sb.Write(buf[:null])
				break
			}
			if err != nil || n != len(buf) {
				break
			}
			sb.Write(buf[:n])
			strOffset += int64(n)
		}
		return sb.String(), nil
	}

	c := g.bufferedCursorAt(strOffset)

	return c.ReadNullTerminatedUTF8String()
}

type FileEntry struct {
	DirStrOffset  uint32
	BaseStrOffset uint32
}

func (g *Gsym) GetFileEntry(index uint32) (FileEntry, error) {
	offset := g.AddressInfoTableOffset() + int64(g.Header.NumAddresses*4)

	// offset: uint32 count
	// offset + 4: uint32(0), uint32(0)

	// and, every entry is 2 uint32s

	offset += 4 + int64(index)*4*2

	c := g.cursorAt(offset)

	entry := FileEntry{}
	var err error

	entry.DirStrOffset, err = c.ReadUint32()
	if err != nil {
		return entry, err
	}

	entry.BaseStrOffset, err = c.ReadUint32()

	return entry, err
}

func (g *Gsym) GetFile(index uint32) (string, error) {
	if index == 0 {
		return "", nil
	}

	entry, err := g.GetFileEntry(index)
	if err != nil {
		return "", err
	}

	dir, err := g.GetString(int64(entry.DirStrOffset))
	if err != nil {
		return "", err
	}

	base, err := g.GetString(int64(entry.BaseStrOffset))
	if err != nil {
		return "", err
	}

	return dir + "/" + base, nil
}

type SourceLocation struct {
	Name   string
	Line   uint32
	Offset uint32
}

type LookupResult struct {
	Address   uint64
	StartAddr uint64
	Size      uint64
	Name      string
	Locations []SourceLocation
}

func (g *Gsym) LookupAddress(addr uint64) (LookupResult, error) {
	return g.LookupTextRelativeAddress(addr - g.Header.BaseAddress)
}

func (g *Gsym) LookupTextRelativeAddress(relAddr uint64) (LookupResult, error) {
	lr := LookupResult{
		Address: relAddr,
	}

	addrIdx, err := g.GetTextRelativeAddressIndex(relAddr)
	if err != nil {
		return lr, err
	}

	entryAddr, err := g.ReadAddressEntry(addrIdx)
	if err != nil {
		return lr, err
	}

	lr.StartAddr = entryAddr

	addrInfoOffset, err := g.GetAddressInfoOffset(addrIdx)
	if err != nil {
		return lr, err
	}

	c := g.bufferedCursorAt(addrInfoOffset)

	fnSize, err := c.ReadUint32()
	if err != nil {
		return lr, err
	}

	lr.Size = uint64(fnSize)

	// check bounds, but only if the function has non-zero size
	notContained := relAddr < entryAddr || relAddr >= entryAddr+uint64(fnSize)
	if notContained && fnSize > 0 {
		return lr, ErrAddressNotFound
	}

	fnNameOffset, err := c.ReadUint32()
	if err != nil {
		return lr, err
	}

	name, err := g.GetString(int64(fnNameOffset))
	if err != nil {
		return lr, err
	}

	lr.Name = name

	lineInfo, err := g.lookupLineInfo(c, entryAddr, relAddr)
	if err != nil {
		return lr, err
	}

	entryLoc := SourceLocation{
		Name:   name,
		Line:   lineInfo.entry.Line,
		Offset: uint32(relAddr - entryAddr),
	}

	lr.Locations = []SourceLocation{entryLoc}

	inlineLocs, err := g.locationsForInlineInfo(lineInfo.inline, relAddr)
	if err != nil {
		return lr, err
	}

	if len(inlineLocs) == 0 {
		return lr, err
	}

	lr.Locations = []SourceLocation{}

	// ok, this is really annoying. The inline info
	// modifies the previous information. So, we have
	// to keep track and change as we go. Also, of course,
	// the array is in the reverse order.
	for i := len(inlineLocs) - 1; i >= 0; i-- {
		loc := inlineLocs[i]
		adjustedLoc := loc

		adjustedLoc.Line = entryLoc.Line

		entryLoc = loc

		lr.Locations = append(lr.Locations, adjustedLoc)
	}

	return lr, err
}

type InfoType uint32

const (
	InfoTypeEndOfList InfoType = 0
	InfoTypeLineTable InfoType = 1
	InfoTypeInline    InfoType = 2
)

type lineInfoResult struct {
	entry  LineEntry
	inline inlineInfo
}

func (g *Gsym) lookupLineInfo(
	c binarycursor.BinaryCursor,
	startAddr, addr uint64,
) (lineInfoResult, error) {
	done := false

	result := lineInfoResult{}

	for !done {
		infoType, err := c.ReadUint32()
		if err != nil {
			return result, err
		}

		_, err = c.ReadUint32()
		if err != nil {
			return result, err
		}

		switch InfoType(infoType) {
		case InfoTypeEndOfList:
			done = true
		case InfoTypeLineTable:
			result.entry, err = lookupLineTable(&c, startAddr, addr)
			if err != nil {
				return result, err
			}
		case InfoTypeInline:
			result.inline, err = decodeInlineInfo(&c, startAddr)
			if err != nil {
				return result, err
			}
		}
	}

	return result, nil
}

func (g *Gsym) locationsForInlineInfo(info inlineInfo, addr uint64) ([]SourceLocation, error) {
	locations := []SourceLocation{}

	if !info.Contains(addr) {
		return locations, nil
	}

	name, err := g.GetString(int64(info.NameOffset))
	if err != nil {
		return locations, err
	}

	loc := SourceLocation{
		Name:   name,
		Line:   info.Line,
		Offset: uint32(addr - info.Ranges[0].Start),
	}

	locations = append(locations, loc)

	for _, child := range info.Children {
		sublocs, err := g.locationsForInlineInfo(child, addr)
		if err != nil {
			return locations, err
		}

		locations = append(locations, sublocs...)
	}

	return locations, nil
}

func (g *Gsym) Close() {
	_ = g.readerAt.Close()
}

type LineEntry struct {
	Address   uint64
	FileIndex uint32
	Line      uint32
}

type LineTableOpCode uint8

const (
	LineTableOpEndSequence  LineTableOpCode = 0x00
	LineTableOpSetFile      LineTableOpCode = 0x01
	LineTableOpAdvancePC    LineTableOpCode = 0x02
	LineTableOpAdvanceLine  LineTableOpCode = 0x03
	LineTableOpFirstSpecial LineTableOpCode = 0x04
)

func lookupLineTable(c *binarycursor.BinaryCursor, startAddr, addr uint64) (LineEntry, error) {
	entry := LineEntry{
		Address: startAddr,
	}

	minDelta, err := c.ReadSleb128()
	if err != nil {
		return LineEntry{}, err
	}

	maxDelta, err := c.ReadSleb128()
	if err != nil {
		return LineEntry{}, err
	}

	lineRange := maxDelta - minDelta + 1
	firstLine, err := c.ReadUleb128()
	if err != nil {
		return LineEntry{}, err
	}

	entry.FileIndex = 1
	entry.Line = uint32(firstLine)

	nextEntry := entry

	done := false

	for !done {
		op, err := c.ReadUint8()
		if err != nil {
			return entry, err
		}

		switch LineTableOpCode(op) {
		case LineTableOpEndSequence:
			done = true
		case LineTableOpSetFile:
			idx, err := c.ReadUleb128()
			if err != nil {
				return entry, err
			}

			nextEntry.FileIndex = uint32(idx)
		case LineTableOpAdvancePC:
			addrDelta, err := c.ReadUleb128()
			if err != nil {
				return entry, err
			}

			nextEntry.Address += addrDelta
		case LineTableOpAdvanceLine:
			lineDelta, err := c.ReadUleb128()
			if err != nil {
				return entry, err
			}

			nextEntry.Line += uint32(lineDelta)
		default:
			// op contains both address and line increment
			adjusted := op - uint8(LineTableOpFirstSpecial)
			lineDelta := minDelta + (int64(adjusted) % lineRange)
			addrDelta := int64(adjusted) / lineRange

			nextEntry.Line += uint32(lineDelta)
			nextEntry.Address += uint64(addrDelta)
		}

		if nextEntry.Address > addr {
			return entry, nil
		}

		entry = nextEntry
	}

	// if we get to the end, return the last entry
	return entry, nil
}

type addressRange struct {
	Start uint64
	Size  uint64
}

func (r addressRange) End() uint64 {
	return r.Start + r.Size
}

func decodeAddressRanges(c *binarycursor.BinaryCursor, baseAddr uint64) ([]addressRange, error) {
	ranges := []addressRange{}

	length, err := c.ReadUleb128()
	if err != nil {
		return ranges, err
	}

	for i := 0; i < int(length); i++ {
		r := addressRange{}

		v, err := c.ReadUleb128()
		if err != nil {
			return ranges, err
		}

		r.Start = v + baseAddr

		v, err = c.ReadUleb128()
		if err != nil {
			return ranges, err
		}

		r.Size = v

		ranges = append(ranges, r)
	}

	return ranges, nil
}

type inlineInfo struct {
	NameOffset uint32
	FileIndex  uint32
	Line       uint32
	Offset     uint64
	Ranges     []addressRange
	Children   []inlineInfo
}

func (i inlineInfo) Ending() bool {
	// the tree terminates with empty ranges
	return len(i.Ranges) == 0
}

func (i inlineInfo) Contains(addr uint64) bool {
	if len(i.Ranges) == 0 {
		return false
	}

	for _, r := range i.Ranges {
		if addr >= r.Start && addr <= r.End() {
			return true
		}
	}

	return false
}

func decodeInlineInfo(c *binarycursor.BinaryCursor, startAddr uint64) (inlineInfo, error) {
	info := inlineInfo{}

	ranges, err := decodeAddressRanges(c, startAddr)
	if err != nil {
		return info, err
	}

	info.Ranges = ranges

	if info.Ending() {
		return info, nil
	}

	hasChildren, err := c.ReadUint8()
	if err != nil {
		return info, err
	}

	nameStrOffset, err := c.ReadUint32()
	if err != nil {
		return info, err
	}

	info.NameOffset = nameStrOffset

	fileIndex, err := c.ReadUleb128()
	if err != nil {
		return info, err
	}

	info.FileIndex = uint32(fileIndex)

	line, err := c.ReadUleb128()
	if err != nil {
		return info, err
	}

	info.Line = uint32(line)

	childBaseAddr := ranges[0].Start // always relative to the parent address
	for hasChildren == 1 {
		child, err := decodeInlineInfo(c, childBaseAddr)
		if err != nil {
			return info, err
		}

		if child.Ending() {
			break
		}

		info.Children = append(info.Children, child)
	}

	return info, nil
}
