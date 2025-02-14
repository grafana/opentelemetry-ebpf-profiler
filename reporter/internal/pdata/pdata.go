// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package pdata // import "go.opentelemetry.io/ebpf-profiler/reporter/internal/pdata"

import (
	lru "github.com/elastic/go-freelru"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/collector/pdata/pprofile"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/xsync"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
)

// Pdata holds the cache for the data used to generate the events reporters
// will export when handling OTLP data.
type Pdata struct {
	// samplesPerSecond is the number of samples per second.
	samplesPerSecond int

	// Executables stores metadata for executables.
	Executables *lru.SyncedLRU[libpf.FileID, samples.ExecInfo]

	// Frames maps frame information to its source location.
	Frames *lru.SyncedLRU[
		libpf.FileID,
		*xsync.RWMutex[map[libpf.AddressOrLineno]samples.SourceInfo],
	]

	// ExtraSampleAttrProd is an optional hook point for adding custom
	// attributes to samples.
	ExtraSampleAttrProd samples.SampleAttrProducer

	ExtraNativeFrameSymbolizer samples.NativeFrameSymbolizer
}

func New(samplesPerSecond int, executablesCacheElements, framesCacheElements uint32, extra samples.SampleAttrProducer, sym samples.NativeFrameSymbolizer) (*Pdata, error) {
	executables, err :=
		lru.NewSynced[libpf.FileID, samples.ExecInfo](executablesCacheElements, libpf.FileID.Hash32)
	if err != nil {
		return nil, err
	}
	executables.SetLifetime(ExecutableCacheLifetime) // Allow GC to clean stale items.
	executables.SetOnEvict(func(id libpf.FileID, info samples.ExecInfo) {

	})

	frames, err := lru.NewSynced[libpf.FileID,
		*xsync.RWMutex[map[libpf.AddressOrLineno]samples.SourceInfo]](
		framesCacheElements, libpf.FileID.Hash32)
	if err != nil {
		return nil, err
	}
	frames.SetLifetime(FramesCacheLifetime) // Allow GC to clean stale items.

	return &Pdata{
		samplesPerSecond:    samplesPerSecond,
		Executables:         executables,
		Frames:              frames,
		ExtraSampleAttrProd: extra,

		ExtraNativeFrameSymbolizer: sym,
	}, nil
}

// Purge purges all the expired data
func (p *Pdata) Purge() {
	p.Executables.PurgeExpired()
	p.Frames.PurgeExpired()
}

func (p Pdata) symbolizeNativeFrame(pid int64, loc *pprofile.Location, traceInfo *samples.TraceEvents, i int, funcMap map[samples.FuncInfo]int32) {
	if p.ExtraNativeFrameSymbolizer == nil {
		return
	}
	fileID := traceInfo.Files[i]
	addr := traceInfo.Linenos[i]
	frameID := libpf.NewFrameID(fileID, addr)
	frameKnown := func(frameID libpf.FrameID) bool {
		known := false
		if frameMapLock, exists := p.Frames.GetAndRefresh(frameID.FileID(),
			FramesCacheLifetime); exists {
			frameMap := frameMapLock.RLock()
			defer frameMapLock.RUnlock(&frameMap)
			_, known = (*frameMap)[frameID.AddressOrLine()]
		}
		return known
	}
	symbolizeSI := func(si samples.SourceInfo) {
		if si.FunctionName != "" {
			line := loc.Line().AppendEmpty()
			line.SetFunctionIndex(createFunctionEntry(funcMap,
				si.FunctionName, ""))
		} else {
			//todo add libfoo.so + 0xefef function for pyroscope rendering?
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
		if len(symbols) == 0 {
			return samples.SourceInfo{}
		}
		sym0 := symbols[0]
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

	if !frameKnown(frameID) {
		symbols, err := p.ExtraNativeFrameSymbolizer.Lookup(fileID, uint64(addr))
		if err != nil {
			if err != nil {
				logrus.Error("msg", "Failed to symbolize native frame",
					"fileID", fileID,
					"addr", addr,
					"err", err,
					"pid", pid,
				)
			}
		}
		if len(symbols) > 0 {
			si := frameMetadata(symbols)
			symbolizeSI(si)
		}
		return
	}

	fileIDInfoLock, exists := p.Frames.GetAndRefresh(fileID,
		FramesCacheLifetime)
	if !exists {
		return
	}
	fileIDInfo := fileIDInfoLock.RLock()
	defer fileIDInfoLock.RUnlock(&fileIDInfo)

	if si, exists := (*fileIDInfo)[addr]; exists {
		symbolizeSI(si)
	}
}
