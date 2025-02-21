package controller

import (
	"flag"

	"go.opentelemetry.io/ebpf-profiler/internal/controller"
)

func RegisterPyroscopeFlags(fs *flag.FlagSet, args *controller.Config) {
	fs.BoolVar(&args.SymbolizeNativeFrames, "pyroscope-symbolize-native-frames", true, "")
	fs.IntVar(
		&args.StackDeltaLimitBytes,
		"pyroscope-stack-delta-limit-bytes",
		0,
		"<=0 means no limit",
	)
	fs.IntVar(
		&args.StackDeltaElfSizeLimitBytes,
		"pyroscope-stack-delta-elf-size-limit-bytes",
		0,
		"<=0 means no limit",
	)
	fs.IntVar(
		&args.SymbCacheSizeBytes,
		"pyroscope-symb-cache-size-bytes",
		2*1024*1024*1024,
		"",
	)
	fs.StringVar(&args.SymbCachePath, "pyroscope-symb-cache-path", "/tmp/symb-cache", "")
}
