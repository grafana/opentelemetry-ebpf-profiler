package gsym

import (
	"cmp"
	"os"
	"slices"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/ebpf-profiler/pyroscope/symb/ffi"
)

type rangeCollector struct {
	w *Writer

	entries []rangeEntry
}
type rangeEntry struct {
	va     uint64
	length uint32
	depth  uint32
	fun    StringOffset
}

func (rc *rangeCollector) VisitRange(va uint64, length, depth uint32, function string) {
	rc.entries = append(rc.entries, rangeEntry{
		va:     va,
		length: length,
		depth:  depth,
		fun:    rc.w.AddString(function),
	})
}

func (rc *rangeCollector) eachFunc(f func([]rangeEntry)) {
	slices.SortFunc(rc.entries, func(a, b rangeEntry) int {
		vacmp := cmp.Compare(a.va, b.va)
		if vacmp == 0 {
			return cmp.Compare(a.depth, b.depth)
		}
		return vacmp
	})
	l := 0
	r := 1
	for r < len(rc.entries) {
		if rc.entries[r].depth == 0 {
			f(rc.entries[l:r])
			l = r
		}
		r++
	}
	if l < len(rc.entries) {
		f(rc.entries[l:])
	}
}

func FDToGSym(executable, output *os.File) error {
	w := NewWriter()
	rc := &rangeCollector{w: w}

	if err := ffi.RangeExtractor(executable, rc); err != nil {
		return err
	}
	rc.eachFunc(func(entries []rangeEntry) {
		root := entries[0]
		info := FunctionInfo{
			Addr: root.va,
			Size: root.length,
			Name: root.fun,
		}
		if len(entries) > 1 {
			info.InlineInfo = buildInlineInfo(entries)
		}
		w.AddFuncInfo(info)
	})
	err := w.Encode(output)
	if err != nil {
		return err
	}
	log.Debugf("converted %s -> %s ", executable.Name(), output.Name())

	return nil
}

func buildInlineInfo(entries []rangeEntry) *InlineInfo {
	res := make([]InlineInfo, len(entries))
	for i := 0; i < len(entries); i++ {
		res[i].Name = entries[i].fun
		res[i].Ranges = []AddressRange{{
			Start: entries[i].va,
			End:   entries[i].va + uint64(entries[i].length),
		}}
		res[i].Name = entries[i].fun
		for j := i - 1; j >= 0; j-- {
			if entries[j].depth == entries[i].depth-1 {
				res[j].Children = append(res[j].Children, &res[i])
				break
			}
		}
	}
	return &res[0]
}
