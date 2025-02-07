package gsym

import (
	"cmp"
	"os"
	"slices"
	"unsafe"
)

type FunctionInfo struct {
	Addr       uint64
	Size       uint32
	Name       StringOffset
	InlineInfo *InlineInfo
}

type AddressData struct {
	Type uint32
	Data []byte
}

type Writer struct {
	hdr Header

	addressData []FunctionInfo

	files   []FileEntry
	strtab  []byte
	strings map[string]StringOffset
}

type StringOffset uint32

func NewWriter() *Writer {
	w := &Writer{strings: make(map[string]StringOffset)}
	w.AddString("")
	return w
}

func (b *Writer) AddString(s string) StringOffset {
	if id, exists := b.strings[s]; exists {
		return id
	}

	id := StringOffset(len(b.strtab))
	b.strings[s] = id
	b.strtab = append(b.strtab, s...)
	b.strtab = append(b.strtab, 0)
	return id
}

func (b *Writer) AddFuncInfo(fi FunctionInfo) {
	if fi.InlineInfo != nil && !fi.InlineInfo.IsValid() {
		return
	}
	b.addressData = append(b.addressData, fi)
}

func (b *Writer) Encode(f *os.File) error {

	slices.SortFunc(b.addressData, func(a, b FunctionInfo) int {
		return cmp.Compare(a.Addr, b.Addr)
	})

	b.hdr.Magic = GSYM_MAGIC
	b.hdr.Version = GSYM_VERSION
	b.hdr.NumAddresses = uint32(len(b.addressData))

	if len(b.addressData) == 0 {
		b.hdr.AddrOffSize = 1
	} else {
		maxAddr := b.addressData[len(b.addressData)-1].Addr
		offset := maxAddr - b.hdr.BaseAddress
		switch {
		case offset <= 0xFF:
			b.hdr.AddrOffSize = 1
		case offset <= 0xFFFF:
			b.hdr.AddrOffSize = 2
		case offset <= 0xFFFFFFFF:
			b.hdr.AddrOffSize = 4
		default:
			b.hdr.AddrOffSize = 8
		}
	}

	w := NewFileWriter(f)

	w.WriteU32(b.hdr.Magic)
	w.WriteU16(b.hdr.Version)
	w.WriteU8(b.hdr.AddrOffSize)
	w.WriteU8(b.hdr.UUIDSize)
	w.WriteU64(b.hdr.BaseAddress)
	w.WriteU32(b.hdr.NumAddresses)
	w.WriteU32(b.hdr.StrtabOffset)
	w.WriteU32(b.hdr.StrtabSize)
	w.Write(b.hdr.UUID[:])

	w.AlignTo(int64(b.hdr.AddrOffSize))

	for _, funcInfo := range b.addressData {
		addrOffset := funcInfo.Addr - b.hdr.BaseAddress
		switch b.hdr.AddrOffSize {
		case 1:
			w.WriteU8(uint8(addrOffset))
		case 2:
			w.WriteU16(uint16(addrOffset))
		case 4:
			w.WriteU32(uint32(addrOffset))
		case 8:
			w.WriteU64(addrOffset)
		}
	}

	w.AlignTo(4)
	addrInfoOffsetsOffset := w.Tell()
	for range b.addressData {
		w.WriteU32(0)
	}

	w.AlignTo(4)
	w.WriteU32(uint32(len(b.files)))
	for _, file := range b.files {
		w.WriteU32(file.DirStrOffset)
		w.WriteU32(file.BaseStrOffset)
	}

	strtabOffset := w.Tell()
	w.Write(b.strtab)
	strtabSize := w.Tell() - strtabOffset

	addrInfoOffsets := make([]uint32, 0, len(b.addressData))
	for _, funcInfo := range b.addressData {
		w.AlignTo(4)
		offset := uint32(w.Tell())
		addrInfoOffsets = append(addrInfoOffsets, offset)
		funcInfo.encode(w)
	}

	w.Flush()
	w.Fixup32(uint32(strtabOffset), 20) // 20 is offset of StrtabOffset in Header
	w.Fixup32(uint32(strtabSize), 24)   // 24 is offset of StrtabSize in Header

	if len(addrInfoOffsets) > 0 {
		addrInfoOffsetsByteSlice := unsafe.Slice((*byte)(unsafe.Pointer(&addrInfoOffsets[0])), len(addrInfoOffsets)*4)
		w.Fixup(addrInfoOffsetsByteSlice, addrInfoOffsetsOffset)
	}
	return w.err
}

func (b *Writer) str(o StringOffset) []byte {
	res := b.strtab[o:]
	if i := slices.Index(res, 0); i != -1 {
		res = res[:i]
	}
	return res
}
