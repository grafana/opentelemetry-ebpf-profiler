package pdata

import (
	"context"
	log2 "github.com/go-kit/log"
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
	sd           *pyroscope.DiscovererWithMetrics
	pyroscopeSD  sd2.TargetFinder
}

func NewPyroPlug() (*PyroPlug, error) {
	logger := log2.NewLogfmtLogger(log2.NewSyncWriter(os.Stderr))

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
		sd:          sd,
		pyroscopeSD: pyrosd,
	}, nil
}

func (r *PyroPlugProc) Symbolize(loc *pprofile.Location, traceInfo *samples.TraceEvents, i int, funcMap map[samples.FuncInfo]int32,
) {
	// this is a temporary hack to symbolize the frames on the client instead of the server
	r.r.symcachelock.Lock()
	defer r.r.symcachelock.Unlock()

	//l := loc.Line().AppendEmpty()
	//funcIndex := createFunctionEntry(funcMap, sym.Name, sym.Module)
	//l.SetFunctionIndex(funcIndex)
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
	return PyroPlugProc{
		r:      r,
		pk:     pk,
		target: pyroscopeTarget,
	}
}

type PyroPlugProc struct {
	r      *PyroPlug
	pk     symtab.PidKey
	target *sd2.Target
}
