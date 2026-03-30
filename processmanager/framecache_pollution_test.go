package processmanager // import "go.opentelemetry.io/ebpf-profiler/processmanager"

// TestNativeFrameCachePollution reproduces the bug where a Go binary's
// symbolization result for a native (libc) frame poisons the frame cache for
// ALL other processes, because native frames do not include the PID in the
// cache key (FRAME_FLAG_PID_SPECIFIC is not set for native frames).
//
// Scenario (matches what was observed in production):
//
//  1. gh (GitHub CLI, a Go binary) makes a read() syscall.  While in that
//     syscall the CPU samples gh at libc offset 0x6ec83 (__syscall_cancel).
//     gh's Go interpreter looks up 0x6ec83 in gh's pclntab and finds
//     runtime.traceReadCPU, so the frame is cached as a GoFrame under key
//     {pid=0, data=<frame bytes>}.
//
//  2. cat (a plain C binary) later runs read() through the exact same libc
//     stub.  The frame bytes are identical → cache HIT → cat's trace gets
//     gh's cached GoFrame{fn="runtime.traceReadCPU"} even though cat has no
//     Go interpreter and runtime.traceReadCPU is meaningless for it.
//
// The root cause is in HandleTrace (manager.go):
//
//	key := frameCacheKey{}
//	if frame.Flags().PIDSpecific() {   // false for native frames
//	    key.pid = pid
//	}
//	copy(key.data[:], frame)
//	// pid is omitted from the key → shared across all processes

import (
	"testing"

	lru "github.com/elastic/go-freelru"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/util"
)

// goInterpreterFake is a fake Go interpreter for a single address.
// When Symbolize is called on a native frame at targetAddr it returns a
// GoFrame with the given function name, mimicking the real Go pclntab lookup.
type goInterpreterFake struct {
	interpreter.InstanceStubs
	targetAddr uint64
	fnName     string
	srcFile    string
}

func (g *goInterpreterFake) Symbolize(
	ef libpf.EbpfFrame,
	frames *libpf.Frames,
	mapping libpf.FrameMapping,
) error {
	if !ef.Type().IsInterpType(libpf.Native) {
		return interpreter.ErrMismatchInterpreterType
	}
	if ef.Data() != g.targetAddr {
		return interpreter.ErrMismatchInterpreterType
	}
	frames.Append(&libpf.Frame{
		Type:            libpf.GoFrame,
		AddressOrLineno: libpf.AddressOrLineno(ef.Data()),
		Mapping:         mapping,
		FunctionName:    libpf.Intern(g.fnName),
		SourceFile:      libpf.Intern(g.srcFile),
	})
	return nil
}

func (g *goInterpreterFake) Detach(_ interpreter.EbpfHandler, _ libpf.PID) error {
	return nil
}

// captureReporter implements reporter.TraceReporter and keeps the last trace.
type captureReporter struct {
	lastTrace *libpf.Trace
}

func (r *captureReporter) ReportTraceEvent(trace *libpf.Trace, _ *samples.TraceEventMeta) error {
	r.lastTrace = trace
	return nil
}

// Ensure captureReporter satisfies the interface.
var _ reporter.TraceReporter = (*captureReporter)(nil)

func TestNativeFrameCachePollution(t *testing.T) {
	const (
		// libcAddr is an offset within libc.so.6 (__syscall_cancel+0x13).
		// In the real bug this is 0x6ec83 and gh's pclntab maps it to
		// runtime.traceReadCPU.
		libcAddr = uint64(0x6ec83)

		// goPID is a Go binary's PID (simulates gh or similar).
		goPID = libpf.PID(100)
		// cPID is a plain C binary's PID (simulates cat, irqbalance, etc.).
		cPID = libpf.PID(200)
	)

	// Build the frame cache the same way the real ProcessManager does.
	frameCache, err := lru.New[frameCacheKey, libpf.Frames](
		frameCacheSize, hashFrameCacheKey)
	require.NoError(t, err)
	frameCache.SetLifetime(frameCacheLifetime)

	cr := &captureReporter{}

	// The fake Go interpreter for goPID resolves libcAddr → GoFrame.
	fakeGoInterp := &goInterpreterFake{
		targetAddr: libcAddr,
		fnName:     "runtime.traceReadCPU",
		srcFile:    "/usr/lib/golang/src/runtime/tracecpu.go",
	}
	fakeODID := util.OnDiskFileIdentifier{DeviceID: 42, InodeNum: 1}

	pm := ProcessManager{
		// goPID has the fake Go interpreter; cPID has nothing.
		interpreters: map[libpf.PID]map[util.OnDiskFileIdentifier]interpreter.Instance{
			goPID: {fakeODID: fakeGoInterp},
			cPID:  {},
		},
		pidToProcessInfo: map[libpf.PID]*processInfo{
			goPID: {},
			cPID:  {},
		},
		frameCache:    frameCache,
		traceReporter: cr,
	}

	// Build a native EbpfFrame for libcAddr.
	// Layout (see libpf/trace.go): ef[0] = type|flags|length|addr, ef[1] = fileID.
	// NewEbpfFrame with length=2 allocates [ef[0], ef[1]]; ef[1]=fileID defaults to 0.
	nativeFrame := libpf.NewEbpfFrame(libpf.NativeFrame, 0 /*no PIDSpecific*/, 2, libcAddr)
	// ef[1] is already 0 (fileID = 0, irrelevant for the test)

	makeTrace := func(pid libpf.PID) *libpf.EbpfTrace {
		buf := make([]uint64, len(nativeFrame))
		copy(buf, nativeFrame)
		return &libpf.EbpfTrace{
			PID:       pid,
			FrameData: buf,
			NumFrames: 1,
		}
	}

	// ── Step 1: process goPID's trace ────────────────────────────────────────
	// The Go interpreter symbolizes libcAddr as runtime.traceReadCPU and the
	// result is cached under key {pid=0, data=nativeFrame[:3]}.
	pm.HandleTrace(makeTrace(goPID))
	require.NotNil(t, cr.lastTrace)

	goTrace := cr.lastTrace
	require.Len(t, goTrace.Frames, 1)
	assert.Equal(t, libpf.GoFrame, goTrace.Frames[0].Value().Type,
		"goPID: frame should be GoFrame after Go interpreter symbolization")
	assert.Equal(t, "runtime.traceReadCPU",
		goTrace.Frames[0].Value().FunctionName.String(),
		"goPID: function name should be runtime.traceReadCPU")

	// ── Step 2: process cPID's trace with the SAME frame bytes ───────────────
	// cPID has no Go interpreter.  Under correct behaviour it should get a
	// plain NativeFrame with no function name.
	// Due to the bug the cache key has pid=0 (PIDSpecific flag was not set),
	// so cPID hits goPID's cached entry and gets a GoFrame instead.
	pm.HandleTrace(makeTrace(cPID))
	require.NotNil(t, cr.lastTrace)

	cTrace := cr.lastTrace
	require.Len(t, cTrace.Frames, 1)

	// BUG: cPID (a C process) gets a GoFrame with runtime.traceReadCPU because
	// the frame cache key does not include the PID for native frames.
	// Once the bug is fixed, the assertions below should be flipped:
	//   assert.Equal(t, libpf.NativeFrame, ...)
	//   assert.Equal(t, "", cTrace.Frames[0].FunctionName.String())
	assert.Equal(t, libpf.GoFrame, cTrace.Frames[0].Value().Type,
		"BUG: cPID got goPID's cached GoFrame — cache key missing PID for native frames")
	assert.Equal(t, "runtime.traceReadCPU",
		cTrace.Frames[0].Value().FunctionName.String(),
		"BUG: cPID got goPID's Go function name from poisoned cache")
}
