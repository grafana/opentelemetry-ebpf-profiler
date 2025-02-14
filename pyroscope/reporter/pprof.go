package reporter

import (
	"bytes"
	"context"
	"fmt"
	"maps"
	"sync"
	"time"

	"github.com/elastic/go-freelru"
	lru "github.com/elastic/go-freelru"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/google/pprof/profile"
	"github.com/zeebo/xxh3"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/xsync"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/pyroscope/sd"
	reporter2 "go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/support"
)

type PPROF struct {
	Raw    []byte
	Target *sd.Target
	Origin libpf.Origin
}
type PPROFConsumer interface {
	Next(p []PPROF)
}

type Config struct {
	CGroupCacheElements      uint32
	ReportInterval           time.Duration
	SamplesPerSecond         int64
	ExecutablesCacheElements uint32
	FramesCacheElements      uint32

	ExtraNativeFrameSymbolizer samples.NativeFrameSymbolizer
	Consumer                   PPROFConsumer
}
type PPROFReporter struct {
	cfg         *Config
	log         log.Logger
	cgroupv2ID  *freelru.SyncedLRU[libpf.PID, string]
	traceEvents xsync.RWMutex[map[libpf.Origin]samples.KeyToEventMapping]
	Executables *lru.SyncedLRU[libpf.FileID, samples.ExecInfo]
	Frames      *lru.SyncedLRU[
		libpf.FileID,
		*xsync.RWMutex[map[libpf.AddressOrLineno]samples.SourceInfo],
	]

	sd              sd.TargetFinder
	wg              sync.WaitGroup
	cancelReporting context.CancelFunc
}

func NewPPROF(log log.Logger, cfg *Config, sd sd.TargetFinder) (*PPROFReporter, error) {
	cgroupv2ID, err := lru.NewSynced[libpf.PID, string](cfg.CGroupCacheElements,
		func(pid libpf.PID) uint32 { return uint32(pid) })
	if err != nil {
		return nil, err
	}
	// Set a lifetime to reduce risk of invalid data in case of PID reuse.
	cgroupv2ID.SetLifetime(90 * time.Second)

	originsMap := make(map[libpf.Origin]samples.KeyToEventMapping, 2)
	for _, origin := range []libpf.Origin{support.TraceOriginSampling,
		support.TraceOriginOffCPU} {
		originsMap[origin] = make(samples.KeyToEventMapping)
	}
	executables, err :=
		lru.NewSynced[libpf.FileID, samples.ExecInfo](cfg.ExecutablesCacheElements, libpf.FileID.Hash32)
	if err != nil {
		return nil, err
	}
	executables.SetLifetime(ExecutableCacheLifetime)
	executables.SetOnEvict(func(id libpf.FileID, info samples.ExecInfo) {

	})

	frames, err := lru.NewSynced[libpf.FileID,
		*xsync.RWMutex[map[libpf.AddressOrLineno]samples.SourceInfo]](
		cfg.FramesCacheElements, libpf.FileID.Hash32)
	if err != nil {
		return nil, err
	}
	frames.SetLifetime(FramesCacheLifetime)

	return &PPROFReporter{
		cfg:         cfg,
		log:         log,
		cgroupv2ID:  cgroupv2ID,
		traceEvents: xsync.NewRWMutex(originsMap),
		Executables: executables,
		Frames:      frames,
		sd:          sd,
	}, nil
}

func (p *PPROFReporter) ReportFramesForTrace(trace *libpf.Trace) {

}

func (p *PPROFReporter) ReportCountForTrace(traceHash libpf.TraceHash, count uint16, meta *samples.TraceEventMeta) {

}

func (p *PPROFReporter) ReportTraceEvent(trace *libpf.Trace, meta *samples.TraceEventMeta) {
	if meta.Origin != support.TraceOriginSampling && meta.Origin != support.TraceOriginOffCPU {
		return
	}

	var extraMeta any

	containerID, err := libpf.LookupCgroupv2(p.cgroupv2ID, meta.PID)
	if err != nil {
		_ = p.log.Log("msg", "Failed to get a cgroupv2 ID as container ID for", "PID", meta.PID, "err", err)
	}

	key := samples.TraceAndMetaKey{
		Hash:           trace.Hash,
		Comm:           meta.Comm,
		ProcessName:    meta.ProcessName,
		ExecutablePath: meta.ExecutablePath,
		ApmServiceName: meta.APMServiceName,
		ContainerID:    containerID,
		Pid:            int64(meta.PID),
		ExtraMeta:      extraMeta,
	}

	traceEventsMap := p.traceEvents.WLock()
	defer p.traceEvents.WUnlock(&traceEventsMap)

	if events, exists := (*traceEventsMap)[meta.Origin][key]; exists {
		events.Timestamps = append(events.Timestamps, uint64(meta.Timestamp))
		events.OffTimes = append(events.OffTimes, meta.OffTime)
		(*traceEventsMap)[meta.Origin][key] = events
		return
	}

	(*traceEventsMap)[meta.Origin][key] = &samples.TraceEvents{
		Files:              trace.Files,
		Linenos:            trace.Linenos,
		FrameTypes:         trace.FrameTypes,
		MappingStarts:      trace.MappingStart,
		MappingEnds:        trace.MappingEnd,
		MappingFileOffsets: trace.MappingFileOffsets,
		Timestamps:         []uint64{uint64(meta.Timestamp)},
		OffTimes:           []int64{meta.OffTime},
	}
}

func (p *PPROFReporter) SupportsReportTraceEvent() bool {
	return true
}

func (p *PPROFReporter) ExecutableKnown(fileID libpf.FileID) bool {
	_, known := p.Executables.GetAndRefresh(fileID, ExecutableCacheLifetime)
	return known
}

func (p *PPROFReporter) ExecutableMetadata(args *reporter2.ExecutableMetadataArgs) {
	p.Executables.Add(args.FileID, samples.ExecInfo{
		FileName:   args.FileName,
		GnuBuildID: args.GnuBuildID,
	})
}

func (p *PPROFReporter) FrameKnown(frameID libpf.FrameID) bool {
	_, known := p.LookupFrame(frameID)
	return known
}

func (p *PPROFReporter) LookupFrame(frameID libpf.FrameID) (samples.SourceInfo, bool) {
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

func (p *PPROFReporter) FrameMetadata(args *reporter2.FrameMetadataArgs) {
	p.frameMetadata(args)
}

func (p *PPROFReporter) frameMetadata(args *reporter2.FrameMetadataArgs) samples.SourceInfo {
	fileID := args.FrameID.FileID()
	addressOrLine := args.FrameID.AddressOrLine()

	if frameMapLock, exists := p.Frames.GetAndRefresh(fileID,
		FramesCacheLifetime); exists {
		frameMap := frameMapLock.WLock()
		defer frameMapLock.WUnlock(&frameMap)

		si := samples.SourceInfo{
			FunctionName:  args.FunctionName,
			FunctionNames: &args.FunctionNames,
		}
		(*frameMap)[addressOrLine] = si
		return si
	}

	v := make(map[libpf.AddressOrLineno]samples.SourceInfo)
	si := samples.SourceInfo{
		FunctionName:  args.FunctionName,
		FunctionNames: &args.FunctionNames,
	}
	v[addressOrLine] = si
	mu := xsync.NewRWMutex(v)
	p.Frames.Add(fileID, &mu)
	return si
}

func (p *PPROFReporter) ReportHostMetadata(metadataMap map[string]string) {
}

func (p *PPROFReporter) ReportHostMetadataBlocking(_ context.Context,
	metadataMap map[string]string, _ int, _ time.Duration) error {
	return nil
}

func (p *PPROFReporter) ReportMetrics(timestamp uint32, ids []uint32, values []int64) {

}

func (p *PPROFReporter) Start(ctx context.Context) error {
	ctx, cancelReporting := context.WithCancel(ctx)
	p.cancelReporting = cancelReporting
	p.wg.Add(1)

	go func() {
		defer p.wg.Done()
		tick := time.NewTicker(p.cfg.ReportInterval)
		defer tick.Stop()
		purgeTick := time.NewTicker(5 * time.Minute)
		defer purgeTick.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				p.reportProfile(ctx)
			case <-purgeTick.C:
				p.Executables.Purge()
				p.Frames.Purge()
				//p.hostmetadata.Purge()
				p.cgroupv2ID.PurgeExpired()
			}
		}
	}()

	return nil
}

func (p *PPROFReporter) Stop() {
	if p.cancelReporting != nil {
		p.cancelReporting()
	}
	p.wg.Wait()
}

func (p *PPROFReporter) GetMetrics() reporter2.Metrics {
	return reporter2.Metrics{}
}

func (p *PPROFReporter) reportProfile(ctx context.Context) {
	traceEvents := p.traceEvents.WLock()
	events := make(map[libpf.Origin]samples.KeyToEventMapping, 2)
	for _, origin := range []libpf.Origin{support.TraceOriginSampling,
		support.TraceOriginOffCPU} {
		events[origin] = maps.Clone((*traceEvents)[origin])
		clear((*traceEvents)[origin])
	}
	p.traceEvents.WUnlock(&traceEvents)

	var profiles []PPROF
	for _, origin := range []libpf.Origin{support.TraceOriginSampling,
		support.TraceOriginOffCPU} {
		originEvents := events[origin]
		if len(originEvents) == 0 {
			continue
		}
		pp := p.createProfile(origin, originEvents)
		profiles = append(profiles, pp...)
	}

	p.cfg.Consumer.Next(profiles)
	sz := 0
	for _, it := range profiles {
		sz += len(it.Raw)
	}
	_ = level.Debug(p.log).Log("msg", "pprof report successful", "count", len(profiles), "total-size", sz)
}

func (p *PPROFReporter) createProfile(
	origin libpf.Origin,
	events map[samples.TraceAndMetaKey]*samples.TraceEvents,
) []PPROF {
	defer func() {
		if p.cfg.ExtraNativeFrameSymbolizer != nil {
			p.cfg.ExtraNativeFrameSymbolizer.Cleanup()
		}
	}()

	bs := NewProfileBuilders(BuildersOptions{
		SampleRate:    int64(p.cfg.SamplesPerSecond),
		PerPIDProfile: true,
	})

	for traceKey, traceInfo := range events {
		target := p.sd.FindTarget(uint32(traceKey.Pid))
		if target == nil {
			continue
		}
		b := bs.BuilderForSample(target, uint32(traceKey.Pid), origin)

		s := b.NewSample(len(traceInfo.FrameTypes))

		switch origin {
		case support.TraceOriginSampling:
			b.AddValue(int64(len(traceInfo.Timestamps)), s)
		case support.TraceOriginOffCPU:
			sum := int64(0)
			for _, t := range traceInfo.OffTimes {
				sum += t
			}
			b.AddValue(sum, s)
		}

		// Walk every frame of the trace.
		for i := range traceInfo.FrameTypes {
			fileId := traceInfo.Files[i]
			addrOrLineNo := traceInfo.Linenos[i]
			frameId := libpf.NewFrameID(fileId, addrOrLineNo)
			location, locationFresh := b.Location(frameId)
			s.Location = append(s.Location, location)
			if !locationFresh {
				continue
			}
			location.Address = uint64(addrOrLineNo)
			switch frameKind := traceInfo.FrameTypes[i]; frameKind {
			case libpf.NativeFrame:
				mapping, mappingFresh := b.Mapping(traceInfo.Files[i])
				if mappingFresh {
					ei, exists := p.Executables.GetAndRefresh(traceInfo.Files[i],
						ExecutableCacheLifetime)

					var fileName = "UNKNOWN"
					if exists {
						fileName = ei.FileName
					}
					mapping.Start = uint64(traceInfo.MappingStarts[i])
					mapping.Limit = uint64(traceInfo.MappingEnds[i])
					mapping.Offset = traceInfo.MappingFileOffsets[i]
					mapping.File = fileName
					mapping.BuildID = ei.GnuBuildID
				}
				location.Mapping = mapping
				p.symbolizeNativeFrame(b, location, traceInfo, i, int(traceKey.Pid))
			case libpf.AbortFrame:
				// Next step: Figure out how the OTLP protocol
				// could handle artificial frames, like AbortFrame,
				// that are not originated from a native or interpreted
				// program.
			default:
				// Store interpreted frame information as a Line message:
				fileIDInfoLock, exists := p.Frames.GetAndRefresh(traceInfo.Files[i],
					FramesCacheLifetime)
				var funcName string
				if !exists {
					funcName = "UNREPORTED"
				} else {
					fileIDInfo := fileIDInfoLock.RLock()
					if si, exists := (*fileIDInfo)[traceInfo.Linenos[i]]; exists {
						funcName = si.FunctionName
					} else {
						funcName = "UNRESOLVED"
					}
					fileIDInfoLock.RUnlock(&fileIDInfo)
				}
				location.Line = []profile.Line{{
					Function: b.Function(funcName)},
				}
			}
		}
	}

	var res []PPROF
	for _, b := range bs.Builders {
		buf := bytes.NewBuffer(nil)
		_, err := b.Write(buf)
		if err != nil {
			p.log.Log("err", err)
			continue
		}
		res = append(res, PPROF{
			Raw:    buf.Bytes(),
			Target: b.Target,
			Origin: origin,
		})
	}
	return res
}

func (p *PPROFReporter) symbolizeNativeFrame(b *ProfileBuilder, loc *profile.Location, traceInfo *samples.TraceEvents, i int, pid int) {

	fileID := traceInfo.Files[i]
	addr := traceInfo.Linenos[i]
	frameID := libpf.NewFrameID(fileID, addr)

	symbolize := func(b *ProfileBuilder, loc *profile.Location, si samples.SourceInfo) {
		if si.FunctionName != "" {
			line := profile.Line{Function: b.Function(si.FunctionName)}
			loc.Line = append(loc.Line, line)
		} else {
			functionName := fmt.Sprintf("%s %x", loc.Mapping.File, loc.Address)
			line := profile.Line{Function: b.Function(functionName)}
			loc.Line = append(loc.Line, line)
		}
		if si.FunctionNames != nil {
			for _, fn := range *si.FunctionNames {
				line := profile.Line{Function: b.Function(fn)}
				loc.Line = append(loc.Line, line)
			}
		}
	}
	si, known := p.LookupFrame(frameID)
	if known {
		symbolize(b, loc, si)
		return
	}
	var symbols []string
	var err error
	if loc.Mapping.File == process.VdsoPathName {
		symbols = nil
	} else {
		symbols, err = p.cfg.ExtraNativeFrameSymbolizer.Lookup(fileID, uint64(addr))
		if err != nil {
			_ = level.Error(p.log).Log("msg", "Failed to symbolize native frame",
				"fileID", fileID,
				"mapping", loc.Mapping.File,
				"addr", addr,
				"err", err,
				"pid", pid,
			)
		}
	}

	var args *reporter2.FrameMetadataArgs
	if len(symbols) > 0 {
		args = &reporter2.FrameMetadataArgs{
			FrameID:       frameID,
			FunctionName:  symbols[0],
			FunctionNames: symbols[1:],
		}
	} else {
		args = &reporter2.FrameMetadataArgs{
			FrameID: frameID,
		}
	}
	si = p.frameMetadata(args)
	symbolize(b, loc, si)
}

const (
	ExecutableCacheLifetime = 1 * time.Hour
	FramesCacheLifetime     = 1 * time.Hour
)

func hashString(s string) uint32 {
	return uint32(xxh3.HashString(s))
}
