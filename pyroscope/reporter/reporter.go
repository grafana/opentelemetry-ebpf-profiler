package reporter

import (
	"fmt"
	"github.com/go-kit/log"
	"go.opentelemetry.io/ebpf-profiler/pyroscope/internalshim/controller"
	"go.opentelemetry.io/ebpf-profiler/pyroscope/internalshim/helpers"
	"go.opentelemetry.io/ebpf-profiler/pyroscope/samples"
	pyrosd "go.opentelemetry.io/ebpf-profiler/pyroscope/sd"
	"go.opentelemetry.io/ebpf-profiler/pyroscope/symb/cache"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/times"
)

func New(log log.Logger, cfg *controller.Config, sd pyrosd.TargetFinder, nfs *cache.FSCache, consumer PPROFConsumer) (reporter.Reporter, error) {
	intervals := times.New(cfg.MonitorInterval,
		cfg.ReporterInterval, cfg.ProbabilisticInterval)
	kernelVersion, err := helpers.GetKernelVersion()
	if err != nil {
		return nil, err
	}
	if cfg.CollAgentAddr == "" {
		return nil, fmt.Errorf("missing otlp collector address")
	}

	// hostname and sourceIP will be populated from the root namespace.
	hostname, sourceIP, err := helpers.GetHostnameAndSourceIP(cfg.CollAgentAddr)
	if err != nil {
		return nil, err
	}
	cfg.HostName, cfg.IPAddress = hostname, sourceIP

	const pprof = true
	if pprof {
		return NewPPROF(log, &Config{
			ExtraNativeFrameSymbolizer: nfs,
			CGroupCacheElements:        1024,
			ReportInterval:             cfg.ReporterInterval,
			SamplesPerSecond:           int64(cfg.SamplesPerSecond),
			ExecutablesCacheElements:   16384,
			FramesCacheElements:        65536,
			Consumer:                   consumer,
		}, sd)
	}
	sap := samples.NewAttributesProviderFromSD(sd)

	reporterConfig := &reporter.Config{
		CollAgentAddr:            cfg.CollAgentAddr,
		DisableTLS:               cfg.DisableTLS,
		MaxRPCMsgSize:            32 << 20, // 32 MiB
		MaxGRPCRetries:           5,
		GRPCOperationTimeout:     intervals.GRPCOperationTimeout(),
		GRPCStartupBackoffTime:   intervals.GRPCStartupBackoffTime(),
		GRPCConnectionTimeout:    intervals.GRPCConnectionTimeout(),
		ReportInterval:           intervals.ReportInterval(),
		ExecutablesCacheElements: 16384,
		// Next step: Calculate FramesCacheElements from numCores and samplingRate.
		FramesCacheElements: 65536,
		CGroupCacheElements: 1024,
		SamplesPerSecond:    cfg.SamplesPerSecond,
		KernelVersion:       kernelVersion,
		HostName:            hostname,
		IPAddress:           sourceIP,

		PyroscopeUsername:          cfg.PyroscopeUsername,
		PyroscopePasswordFile:      cfg.PyroscopePasswordFile,
		ExtranativeFrameSymbolizer: nfs,
		ExtraSampleAttrProd:        sap,
	}
	return reporter.NewOTLP(reporterConfig)

}
