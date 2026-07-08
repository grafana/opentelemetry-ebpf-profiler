package ruby // import "go.opentelemetry.io/ebpf-profiler/interpreter/ruby"

import "sync/atomic"

// ReturnToNative controls whether the Ruby unwinder transitions back to the
// native unwinder for cfunc frames. It is the inverse of the upstream
// Config.SkipNativeResume knob and is kept as a package-level atomic for
// alloy, which toggles it before starting the profiler. The internalshim
// controller translates it into Interpreters.Ruby.SkipNativeResume on start.
var ReturnToNative = atomic.Bool{}

func init() {
	ReturnToNative.Store(true)
}
