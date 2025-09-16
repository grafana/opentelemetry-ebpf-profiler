package samples // import "go.opentelemetry.io/ebpf-profiler/reporter/samples"

import "go.opentelemetry.io/ebpf-profiler/libpf"

// SourceInfo was removed upstream, we still use it for pyroscope symbolization.
// todo remove/rename, switch from NativeSymbolResolver to ExecutableReporter
type SourceInfo struct {
	LineNumber   libpf.SourceLineno
	FunctionName libpf.String
	FilePath     libpf.String
}
