package pdata

import (
	"context"
	log2 "github.com/go-kit/log"
	"github.com/grafana/pyroscope/ebpf/cpp/demangle"
	"github.com/grafana/pyroscope/ebpf/metrics"
	sd2 "github.com/grafana/pyroscope/ebpf/sd"
	"github.com/grafana/pyroscope/ebpf/symtab"
	"go.opentelemetry.io/collector/pdata/pprofile"
	"go.opentelemetry.io/ebpf-profiler/reporter/internal/samples"
	"go.opentelemetry.io/ebpf-profiler/reporter/pyroscope"
	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.4.0"
	"os"
	"sync"
)

type PyroPlug struct {
	symcachelock sync.Mutex
	symcache     *symtab.SymbolCache
	sd           *pyroscope.DiscovererWithMetrics
	pyroscopeSD  sd2.TargetFinder
	pidsDead     map[uint32]struct{}
}

func NewPyroPlug() (*PyroPlug, error) {
	logger := log2.NewLogfmtLogger(log2.NewSyncWriter(os.Stderr))
	symCache, err := symtab.NewSymbolCache(logger, symtab.CacheOptions{
		PidCacheOptions: symtab.GCacheOptions{
			Size:       239,
			KeepRounds: 8,
		},
		BuildIDCacheOptions: symtab.GCacheOptions{
			Size:       239,
			KeepRounds: 8,
		},
		SameFileCacheOptions: symtab.GCacheOptions{
			Size:       239,
			KeepRounds: 8,
		},
	}, metrics.NewSymtabMetrics(nil))
	if err != nil {
		return nil, err
	}

	pyrosdOpt := sd2.TargetsOptions{
		Targets:            nil,
		TargetsOnly:        true,
		DefaultTarget:      nil,
		ContainerCacheSize: 2048,
	}
	pyrosd, err := sd2.NewTargetFinder(os.DirFS("/"), logger, pyrosdOpt)
	if err != nil {
		return nil, err
	}

	cb := func(exports pyroscope.Exports) {
		opt := pyrosdOpt
		opt.Targets = make([]sd2.DiscoveryTarget, 0, len(exports.Targets))
		for _, target := range exports.Targets {
			opt.Targets = append(opt.Targets, pyroscope.ConvertToPyroscopeTarget(target))
		}
		pyrosd.Update(opt)
	}
	var sd *pyroscope.DiscovererWithMetrics
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		sd, err = pyroscope.NewK8SServiceDiscovery(logger, cb)
	} else {
		sd, err = pyroscope.NewDockerServiceDiscovery(logger, cb)
	}
	if err != nil {
		return nil, err
	}

	go func() {
		sd.RunDiscovery(context.Background()) // todo stop
	}()
	return &PyroPlug{
		symcache:    symCache,
		sd:          sd,
		pyroscopeSD: pyrosd,
	}, nil
}

func (r *PyroPlug) Reset() func() {
	r.symcachelock.Lock()
	r.symcache.NextRound()
	r.symcachelock.Unlock()
	r.pidsDead = make(map[uint32]struct{})
	return func() {
		r.symcachelock.Lock()
		defer r.symcachelock.Unlock()
		for pid := range r.pidsDead {
			r.symcache.RemoveDeadPID(symtab.PidKey(pid))
		}
	}
}

func (r *PyroPlugProc) Symbolize(loc *pprofile.Location, traceInfo *samples.TraceEvents, i int, funcMap map[samples.FuncInfo]int32,
) {
	// this is a temporary hack to symbolize the frames on the client instead of the server
	r.r.symcachelock.Lock()
	defer r.r.symcachelock.Unlock()

	if r.proc.Error() != nil {
		r.r.pidsDead[uint32(r.proc.Pid())] = struct{}{}
	} else {
		instructionPointer := uint64(traceInfo.Linenos[i]) + uint64(traceInfo.MappingFileOffsets[i])
		sym := r.proc.Resolve(instructionPointer)
		if sym.Name != "" {
			l := loc.Line().AppendEmpty()
			funcIndex := createFunctionEntry(funcMap, sym.Name, sym.Module)
			l.SetFunctionIndex(funcIndex)
		}
	}
}

func (r *PyroPlugProc) TargetAttributes(attrMgr *samples.AttrTableManager, sample *pprofile.Sample) {
	if r.target != nil {
		_, ls := r.target.Labels()
		for _, lbl := range ls {
			attrMgr.AppendOptionalString(sample.AttributeIndices(), attribute.Key(lbl.Name), lbl.Value)
		}
		if r.target.ServiceName() != "" {
			attrMgr.AppendOptionalString(sample.AttributeIndices(), semconv.ServiceNameKey, r.target.ServiceName())
		}
	}
}

func (r *PyroPlug) Proc(pk symtab.PidKey) PyroPlugProc {
	pyroscopeTarget := r.pyroscopeSD.FindTarget(uint32(pk)) // todo use the new Config.ExtraSampleAttrProd
	proc := r.symcache.GetProcTableCached(pk)
	if proc == nil {
		proc = r.symcache.NewProcTable(pk, &symtab.SymbolOptions{
			GoTableFallback: false,
			DemangleOptions: demangle.DemangleFull,
		})
	}
	return PyroPlugProc{
		r:      r,
		pk:     pk,
		proc:   proc,
		target: pyroscopeTarget,
	}
}

type PyroPlugProc struct {
	r      *PyroPlug
	pk     symtab.PidKey
	proc   *symtab.ProcTable
	target *sd2.Target
}
