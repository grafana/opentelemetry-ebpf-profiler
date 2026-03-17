package ruby // import "go.opentelemetry.io/ebpf-profiler/interpreter/ruby"

import "sync/atomic"

var ReturnToNative = atomic.Bool{}

func init() {
	ReturnToNative.Store(true)
}

func returnToNative() int {
	if ReturnToNative.Load() {
		return 1
	}
	return 0
}
