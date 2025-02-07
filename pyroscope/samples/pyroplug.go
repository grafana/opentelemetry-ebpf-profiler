package samples

import (
	"context"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/pyroscope/promsd"
	"os"
	"sync"

	log2 "github.com/go-kit/log"
	sd2 "github.com/grafana/pyroscope/ebpf/sd"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.4.0"
)

type PyroPlug struct {
	symcachelock sync.Mutex
	sd           sd2.TargetFinder
}

func (p *PyroPlug) CollectExtraSampleMeta(trace *libpf.Trace, meta *samples.TraceEventMeta) any {
	return p.sd.FindTarget(uint32(meta.PID)) // todo this may be bad if sd creates a new target with same labels
}

func (p *PyroPlug) ExtraSampleAttrs(attrMgr *samples.AttrTableManager, meta any) []int32 {
	target, ok := meta.(*sd2.Target)
	if target == nil || !ok {
		return nil
	}
	attrs := pcommon.NewInt32Slice() // id dont like this
	_, ls := target.Labels()
	for _, lbl := range ls {
		attrMgr.AppendOptionalString(attrs, attribute.Key(lbl.Name), lbl.Value)
	}
	if target.ServiceName() != "" {
		attrMgr.AppendOptionalString(attrs, semconv.ServiceNameKey, target.ServiceName())
	}
	return attrs.AsRaw()
}

type Options struct {
	SD                 sd2.TargetsOptions
	Kubernetes, Docker bool
}

func NewSDAttrProd(logger log2.Logger, opt Options) (*PyroPlug, error) {

	pyrosdOpt := opt.SD
	pyrosd, err := sd2.NewTargetFinder(os.DirFS("/"), logger, pyrosdOpt)
	if err != nil {
		return nil, err
	}

	cb := func(exports promsd.Exports) {
		opt := pyrosdOpt
		opt.Targets = make([]sd2.DiscoveryTarget, 0, len(exports.Targets))
		for _, target := range exports.Targets {
			opt.Targets = append(opt.Targets, promsd.ConvertToPyroscopeTarget(target))
		}
		pyrosd.Update(opt)
	}
	var sd *promsd.DiscovererWithMetrics
	if opt.Kubernetes {
		sd, err = promsd.NewK8SServiceDiscovery(logger, cb)
	} else if opt.Docker {
		sd, err = promsd.NewDockerServiceDiscovery(logger, cb)
	}
	if err != nil {
		return nil, err
	}

	if sd != nil {
		go func() {
			sd.RunDiscovery(context.Background()) // todo stop
		}()
	}

	return NewPyroPlugFromSD(pyrosd), nil
}

func NewPyroPlugFromSD(sd sd2.TargetFinder) *PyroPlug {
	return &PyroPlug{
		sd: sd,
	}
}
