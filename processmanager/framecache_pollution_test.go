package processmanager // import "go.opentelemetry.io/ebpf-profiler/processmanager"

import (
	"os"
	"runtime"
	"strings"
	"testing"

	lru "github.com/elastic/go-freelru"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	gointerp "go.opentelemetry.io/ebpf-profiler/interpreter/go"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/util"
)

type captureReporter struct {
	lastTrace *libpf.Trace
}

func (r *captureReporter) ReportTraceEvent(trace *libpf.Trace, _ *samples.TraceEventMeta) error {
	r.lastTrace = trace
	return nil
}

var _ reporter.TraceReporter = (*captureReporter)(nil)

func TestNativeFrameCachePollution(t *testing.T) {
	exec, err := os.Executable()
	require.NoError(t, err)

	pc, _, _, ok := runtime.Caller(0)
	require.True(t, ok)
	frameAddr := uint64(pc)

	libpfPID := libpf.PID(os.Getpid())
	pid := process.New(libpfPID, libpfPID)
	elfRef := pfelf.NewReference(exec, pid)

	hostFileID, err := host.FileIDFromBytes([]byte{0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55})
	require.NoError(t, err)
	loaderInfo := interpreter.NewLoaderInfo(hostFileID, elfRef)
	rm := remotememory.NewProcessVirtualMemory(libpfPID)

	gData, err := gointerp.Loader(nil, loaderInfo)
	require.NoError(t, err)

	gInstance, err := gData.Attach(nil, libpfPID, 0x0, rm)
	require.NoError(t, err)

	{
		sanityFrames := libpf.Frames{}
		ef := libpf.NewEbpfFrame(libpf.NativeFrame, 0, 2, frameAddr)
		require.NoError(t, gInstance.Symbolize(ef, &sanityFrames, libpf.FrameMapping{}))
		require.Len(t, sanityFrames, 1)
		got := sanityFrames[0].Value().FunctionName.String()
		assert.True(t, strings.HasPrefix(got, "go.opentelemetry.io/ebpf-profiler/processmanager"),
			"unexpected function name %q for addr 0x%x", got, frameAddr)
	}

	const (
		goPID = libpf.PID(100)
		cPID  = libpf.PID(200)
	)

	frameCache, err := lru.New[frameCacheKey, libpf.Frames](frameCacheSize, hashFrameCacheKey)
	require.NoError(t, err)
	frameCache.SetLifetime(frameCacheLifetime)

	odid := util.OnDiskFileIdentifier{DeviceID: 42, InodeNum: 1}
	cr := &captureReporter{}

	pm := ProcessManager{
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

	makeTrace := func(pid libpf.PID) *libpf.EbpfTrace {
		ef := libpf.NewEbpfFrame(libpf.NativeFrame, 0, 2, frameAddr)
		buf := make([]uint64, len(ef))
		copy(buf, ef)
		return &libpf.EbpfTrace{PID: pid, FrameData: buf, NumFrames: 1}
	}

	pm.HandleTrace(makeTrace(goPID))
	require.NotNil(t, cr.lastTrace)
	goTrace := cr.lastTrace
	require.Len(t, goTrace.Frames, 1)
	goFrame := goTrace.Frames[0].Value()
	assert.Equal(t, libpf.GoFrame, goFrame.Type)
	assert.True(t, strings.HasPrefix(goFrame.FunctionName.String(),
		"go.opentelemetry.io/ebpf-profiler/processmanager"))

	pm.HandleTrace(makeTrace(cPID))
	require.NotNil(t, cr.lastTrace)
	cTrace := cr.lastTrace
	require.Len(t, cTrace.Frames, 1)
	cFrame := cTrace.Frames[0].Value()

	assert.Equal(t, libpf.NativeFrame, cFrame.Type)
	assert.Equal(t, "", cFrame.FunctionName.String())
}
