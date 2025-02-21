package pdata

import (
	"fmt"

	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/collector/pdata/pprofile"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/xsync"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
)

func (p *Pdata) symbolizeNativeFrame(
	loc pprofile.Location,
	mappingName string,
	traceInfo *samples.TraceEvents,
	i int,
	funcMap map[samples.FuncInfo]int32,
) {
	if p.ExtraNativeSymbolResolver == nil {
		return
	}
	fileID := traceInfo.Files[i]
	addr := traceInfo.Linenos[i]
	frameID := libpf.NewFrameID(fileID, addr)
	LookupFrame := func(frameID libpf.FrameID) (samples.SourceInfo, bool) {
		known := false
		si := samples.SourceInfo{}
		if frameMapLock, exists := p.Frames.GetAndRefresh(frameID.FileID(),
			FramesCacheLifetime); exists {
			frameMap := frameMapLock.RLock()
			defer frameMapLock.RUnlock(&frameMap)
			si, known = (*frameMap)[frameID.AddressOrLine()]
		}
		return si, known
	}
	symbolize := func(si samples.SourceInfo) {
		if si.FunctionName != "" {
			line := loc.Line().AppendEmpty()
			line.SetFunctionIndex(createFunctionEntry(funcMap,
				si.FunctionName, ""))
		} else {
			line := loc.Line().AppendEmpty()
			line.SetFunctionIndex(createFunctionEntry(funcMap,
				fmt.Sprintf("%s %x", mappingName, addr), ""))
		}

		if si.FunctionNames != nil {
			for _, fn := range *si.FunctionNames {
				line := loc.Line().AppendEmpty()
				line.SetFunctionIndex(createFunctionEntry(funcMap,
					fn, ""))
			}
		}
	}
	frameMetadata := func(symbols []string) samples.SourceInfo {
		sym0 := ""
		if len(symbols) > 0 {
			sym0 = symbols[0]
		}
		var sym1 *[]string
		if len(symbols) > 1 {
			tail := symbols[1:]
			sym1 = &tail
		} else {
			sym1 = nil
		}

		si := samples.SourceInfo{
			FunctionName:  sym0,
			FunctionNames: sym1,
		}
		if frameMapLock, exists := p.Frames.GetAndRefresh(fileID,
			FramesCacheLifetime); exists {
			frameMap := frameMapLock.WLock()
			defer frameMapLock.WUnlock(&frameMap)

			(*frameMap)[addr] = si
			return si
		}

		v := make(map[libpf.AddressOrLineno]samples.SourceInfo)
		v[addr] = si
		mu := xsync.NewRWMutex(v)
		p.Frames.Add(fileID, &mu)
		return si
	}
	si, known := LookupFrame(frameID)
	if known {
		symbolize(si)
		return
	}
	var (
		symbols []string
		err     error
	)
	if mappingName != process.VdsoPathName {
		symbols, err = p.ExtraNativeSymbolResolver.ResolveAddress(fileID, uint64(addr))
		if err != nil {
			logrus.Debugf("Failed to symbolize native frame %v:%v: %v", fileID, addr, err)
		}
	}
	si = frameMetadata(symbols)
	symbolize(si)
}
