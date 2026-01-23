package dynamicprofiling // import "go.opentelemetry.io/ebpf-profiler/pyroscope/dynamicprofiling"

import (
	"go.opentelemetry.io/ebpf-profiler/process"
)

type Policy interface {
	ProfilingEnabled(process process.Process, containerID string) bool
}

type AlwaysOnPolicy struct{}

func (a AlwaysOnPolicy) ProfilingEnabled(_ process.Process, _ string) bool {
	return true
}
