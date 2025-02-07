package gsym

type AddressRange struct {
	Start uint64
	End   uint64
}
type AddressRanges []AddressRange

type InlineInfo struct {
	Name     StringOffset
	CallFile uint32
	CallLine uint32
	Ranges   AddressRanges
	Children []*InlineInfo
}

func (ii *InlineInfo) IsValid() bool {
	if len(ii.Ranges) == 0 {
		return false
	}
	for _, r := range ii.Ranges {
		if r.Start >= r.End {
			return false
		}
	}
	for _, child := range ii.Children {
		if !child.IsValid() {
			return false
		}
	}
	return true
}

func (ii *InlineInfo) Encode(w *FileWriter, baseAddr uint64) {
	w.WriteULEB(uint64(len(ii.Ranges)))
	for _, r := range ii.Ranges {
		startOffset := r.Start - baseAddr
		size := r.End - r.Start
		w.WriteULEB(startOffset)
		w.WriteULEB(size)
	}

	hasChildren := len(ii.Children) > 0
	w.WriteU8(boolToU8(hasChildren))

	w.WriteU32(uint32(ii.Name))
	w.WriteULEB(uint64(ii.CallFile))
	w.WriteULEB(uint64(ii.CallLine))

	if hasChildren {
		childBaseAddr := ii.Ranges[0].Start

		for _, child := range ii.Children {
			child.Encode(w, childBaseAddr)
		}

		w.WriteULEB(0)
	}
}

func (ii *InlineInfo) containsRange(r AddressRange) bool {
	for _, parentRange := range ii.Ranges {
		if r.Start >= parentRange.Start && r.End <= parentRange.End {
			return true
		}
	}
	return false
}

func boolToU8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

func (funcInfo *FunctionInfo) encode(w *FileWriter) {
	w.WriteU32(funcInfo.Size)
	w.WriteU32(uint32(funcInfo.Name))
	if funcInfo.InlineInfo != nil && funcInfo.InlineInfo.IsValid() {
		w.WriteU32(uint32(InfoTypeInline))
		//sizeOffset := w.Tell()
		w.WriteU32(0)
		funcInfo.InlineInfo.Encode(w, funcInfo.Addr)
		//w.Fixup32(uint32(w.Tell()-sizeOffset-4), sizeOffset) // it is not used by the reader
	}
	w.WriteU32(uint32(InfoTypeEndOfList))
	w.WriteU32(0)
}
