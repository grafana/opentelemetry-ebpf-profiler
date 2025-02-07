package pdata

import (
	"context"
	"fmt"
	log2 "github.com/go-kit/log"
	sd2 "github.com/grafana/pyroscope/ebpf/sd"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter/internal/samples"
	"go.opentelemetry.io/ebpf-profiler/reporter/pyroscope"
	"go.opentelemetry.io/otel/attribute"
	"os"
	"sync"
)

type PyroPlug struct {
	symcachelock sync.Mutex
	sd           sd2.TargetFinder
}

type PyroPlugOptions struct {
	SD         sd2.TargetsOptions
	Kubernetes bool
	Docker     bool
}

func NewPyroPlug(logger log2.Logger, pyrosd sd2.TargetFinder, opt PyroPlugOptions) (*PyroPlug, error) {
	//logger := log2.NewLogfmtLogger(log2.NewSyncWriter(os.Stderr))
	//
	pyrosdOpt := opt.SD
	//	Targets:            nil,
	//	TargetsOnly:        true,
	//	DefaultTarget:      nil,
	//	ContainerCacheSize: 2048,
	//}
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
	if opt.Kubernetes && opt.Docker {
		return nil, fmt.Errorf("pyroscope plug sd should only enable at most one of docker or kubernetes ")
	}
	var sd *pyroscope.DiscovererWithMetrics
	if opt.Kubernetes {
		sd, err = pyroscope.NewK8SServiceDiscovery(logger, cb)
	} else if opt.Docker {
		sd, err = pyroscope.NewDockerServiceDiscovery(logger, cb)
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

func (r *PyroPlug) CollectExtraSampleMeta(trace *libpf.Trace, meta *samples.TraceEventMeta) any {
	return meta.PID
}

func (r *PyroPlug) ExtraSampleAttrs(attrMgr *samples.AttrTableManager, meta any) []int32 {

	pid, ok := meta.(libpf.PID)
	if !ok {
		return nil
	}

	target := r.sd.FindTarget(uint32(pid))
	if target == nil {
		return nil
	}
	_, ls := target.Labels()
	for _, lbl := range ls {
		attrMgr.AppendOptionalString(sample.AttributeIndices(), attribute.Key(lbl.Name), lbl.Value)
	}
	if r.target.ServiceName() != "" {
		attrMgr.AppendOptionalString(sample.AttributeIndices(), semconv.ServiceNameKey, r.target.ServiceName())
	}
}
