package samples

import (
	"context"
	"sync"

	"github.com/elastic/go-freelru"
	log2 "github.com/go-kit/log"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/pyroscope/promsd"
	"go.opentelemetry.io/ebpf-profiler/pyroscope/sd"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.4.0"
)

type AttributesProvider struct {
	symcachelock sync.Mutex
	Discovery    sd.TargetFinder
}

func (p *AttributesProvider) CollectExtraSampleMeta(trace *libpf.Trace, meta *samples.TraceEventMeta) any {
	return p.Discovery.FindTarget(uint32(meta.PID)) // todo this may be bad if sd creates a new target with same labels
}

func (p *AttributesProvider) ExtraSampleAttrs(attrMgr *samples.AttrTableManager, meta any) []int32 {
	target, ok := meta.(*sd.Target)
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
	SD                 sd.TargetsOptions
	Kubernetes, Docker bool
}

func NewAttributesProvider(logger log2.Logger, cgroups *freelru.SyncedLRU[libpf.PID, string], opt Options) (*AttributesProvider, error) {

	pyrosdOpt := opt.SD
	pyrosd, err := sd.NewTargetFinder(logger, cgroups, pyrosdOpt)
	if err != nil {
		return nil, err
	}

	cb := func(exports promsd.Exports) {
		opt := pyrosdOpt
		opt.Targets = make([]sd.DiscoveryTarget, 0, len(exports.Targets))
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

	return NewAttributesProviderFromSD(pyrosd), nil
}

func NewAttributesProviderFromSD(sd sd.TargetFinder) *AttributesProvider {
	return &AttributesProvider{
		Discovery: sd,
	}
}
