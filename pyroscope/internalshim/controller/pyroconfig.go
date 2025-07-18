package controller // import "go.opentelemetry.io/ebpf-profiler/pyroscope/internalshim/controller"

import (
	"flag"

	"go.opentelemetry.io/ebpf-profiler/internal/controller"
)

func RegisterPyroscopeFlags(fs *flag.FlagSet, args *controller.Config) {
	fs.BoolVar(&args.SymbolizeNativeFrames, "pyroscope-symbolize-native-frames", true, "")
	fs.IntVar(
		&args.SymbCacheSizeEntries,
		"pyroscope-symb-cache-size-entries",
		2048,
		"",
	)
	fs.StringVar(&args.SymbCachePath, "pyroscope-symb-cache-path", "/tmp/symb-cache", "")
	fs.BoolVar(
		&args.PyroscopeDynamicProfilingPolicy,
		"pyroscope-dynamic-profiling-policy",
		true,
		"true for sd targets only profiling policy",
	)
}
