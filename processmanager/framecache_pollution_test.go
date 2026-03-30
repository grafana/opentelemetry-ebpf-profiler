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
	"os"
	"runtime"
	"strings"
	"testing"

	lru "github.com/elastic/go-freelru"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/host"
	gointerp "go.opentelemetry.io/ebpf-profiler/interpreter/go"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/util"
)

// captureReporter implements reporter.TraceReporter and keeps the last trace.
type captureReporter struct {
	lastTrace *libpf.Trace
}

func (r *captureReporter) ReportTraceEvent(trace *libpf.Trace, _ *samples.TraceEventMeta) error {
	r.lastTrace = trace
	return nil
}

var _ reporter.TraceReporter = (*captureReporter)(nil)

func TestNativeFrameCachePollution(t *testing.T) {
	// Load the real Go interpreter from this test binary. The test binary IS a
	// Go binary, so its pclntab contains all runtime functions. We pick any
	// address that resolves to a known function.
	exec, err := os.Executable()
	require.NoError(t, err)

	// runtime.Caller returns the virtual address of this call site. For a
	// non-PIE Go binary the virtual address equals the ELF-space address, so
	// pclntab.Symbolize will find it directly.
	pc, _, _, ok := runtime.Caller(0)
	require.True(t, ok)
	fnPC := runtime.FuncForPC(pc)
	require.NotNil(t, fnPC)
	frameAddr := uint64(pc)

	libpfPID := libpf.PID(os.Getpid())
	pid := process.New(libpfPID, libpfPID)
	elfRef := pfelf.NewReference(exec, pid)

	hostFileID, err := host.FileIDFromBytes([]byte{0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55})
	require.NoError(t, err)
	loaderInfo := interpreter.NewLoaderInfo(hostFileID, elfRef)
	rm := remotememory.NewProcessVirtualMemory(libpfPID)

	gData, err := gointerp.Loader(nil, loaderInfo)
	require.NoError(t, err, "failed to load Go interpreter from test binary")

	gInstance, err := gData.Attach(nil, libpfPID, 0x0, rm)
	require.NoError(t, err)

	// Quick sanity-check: the real interpreter should resolve frameAddr to the
	// current function name.
	{
		sanityFrames := libpf.Frames{}
		ef := libpf.NewEbpfFrame(libpf.NativeFrame, 0, 2, frameAddr)
		require.NoError(t, gInstance.Symbolize(ef, &sanityFrames, libpf.FrameMapping{}))
		require.Len(t, sanityFrames, 1)
		got := sanityFrames[0].Value().FunctionName.String()
		// runtime.Caller returns a return address; the function name may have
		// a "funcN" suffix for anonymous callers, so check for the prefix only.
		assert.True(t, strings.HasPrefix(got, "go.opentelemetry.io/ebpf-profiler/processmanager"),
			"unexpected function name %q for addr 0x%x", got, frameAddr)
	}

	const (
		// goPID simulates the Go binary (e.g. gh) whose interpreter symbolizes
		// the frame and populates the cache.
		goPID = libpf.PID(100)
		// cPID simulates a plain C binary (e.g. cat) with no Go interpreter.
		cPID = libpf.PID(200)
	)

	frameCache, err := lru.New[frameCacheKey, libpf.Frames](frameCacheSize, hashFrameCacheKey)
	require.NoError(t, err)
	frameCache.SetLifetime(frameCacheLifetime)

	odid := util.OnDiskFileIdentifier{DeviceID: 42, InodeNum: 1}
	cr := &captureReporter{}

	pm := ProcessManager{
		// goPID has the real Go interpreter; cPID has none.
		interpreters: map[libpf.PID]map[util.OnDiskFileIdentifier]interpreter.Instance{
			goPID: {odid: gInstance},
			cPID:  {},
		},
		pidToProcessInfo: map[libpf.PID]*processInfo{
			goPID: {},
			cPID:  {},
		},
		frameCache:    frameCache,
		traceReporter: cr,
	}

	// Native EbpfFrame carrying frameAddr (no PIDSpecific flag).
	// Length=2: ef[0]=header|addr, ef[1]=fileID (0, irrelevant here).
	makeTrace := func(pid libpf.PID) *libpf.EbpfTrace {
		ef := libpf.NewEbpfFrame(libpf.NativeFrame, 0 /*no PIDSpecific*/, 2, frameAddr)
		buf := make([]uint64, len(ef))
		copy(buf, ef)
		return &libpf.EbpfTrace{PID: pid, FrameData: buf, NumFrames: 1}
	}

	// ── Step 1: goPID ────────────────────────────────────────────────────────
	// The real Go interpreter symbolizes frameAddr, producing a GoFrame. The
	// result is stored in the cache under key {pid=0, data=frame_bytes}
	// (PID is zero because PIDSpecific is not set for native frames).
	pm.HandleTrace(makeTrace(goPID))
	require.NotNil(t, cr.lastTrace)
	goTrace := cr.lastTrace
	require.Len(t, goTrace.Frames, 1)
	goFrame := goTrace.Frames[0].Value()
	assert.Equal(t, libpf.GoFrame, goFrame.Type,
		"goPID: real Go interpreter should produce a GoFrame")
	assert.True(t, strings.HasPrefix(goFrame.FunctionName.String(),
		"go.opentelemetry.io/ebpf-profiler/processmanager"),
		"goPID: function name should be from this package, got %q", goFrame.FunctionName)

	// ── Step 2: cPID ─────────────────────────────────────────────────────────
	// cPID has no Go interpreter. Correct behaviour: NativeFrame with no name.
	// BUG: because the cache key omits the PID for native frames, cPID gets a
	// cache hit and inherits goPID's GoFrame instead.
	pm.HandleTrace(makeTrace(cPID))
	require.NotNil(t, cr.lastTrace)
	cTrace := cr.lastTrace
	require.Len(t, cTrace.Frames, 1)
	cFrame := cTrace.Frames[0].Value()

	// These assertions document the current (buggy) behaviour.
	// When the bug is fixed they should be:
	//   assert.Equal(t, libpf.NativeFrame, cFrame.Type)
	//   assert.Equal(t, "", cFrame.FunctionName.String())
	assert.Equal(t, libpf.GoFrame, cFrame.Type,
		"BUG: cPID got goPID's cached GoFrame — native frame cache key is missing PID")
	assert.Equal(t, goFrame.FunctionName.String(), cFrame.FunctionName.String(),
		"BUG: cPID got goPID's function name from poisoned cache")
}
