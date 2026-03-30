package processmanager // import "go.opentelemetry.io/ebpf-profiler/processmanager"

import (
	"os"
	"runtime"
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

type traceReporterFunc func(*libpf.Trace, *samples.TraceEventMeta) error

func (f traceReporterFunc) ReportTraceEvent(trace *libpf.Trace, meta *samples.TraceEventMeta) error {
	return f(trace, meta)
}

var _ reporter.TraceReporter = traceReporterFunc(nil)


func TestNativeFrameCachePollution(t *testing.T) {
	exec, err := os.Executable()
	require.NoError(t, err)

	pc, _, _, ok := runtime.Caller(0)
	require.True(t, ok)
	frameAddr := uint64(pc)
	expectedFuncName := runtime.FuncForPC(pc).Name()

	goPID := libpf.PID(os.Getpid())
	cPID := goPID+1
	elfRef := pfelf.NewReference(exec, process.New(goPID, goPID))

	require.NoError(t, err)
	loaderInfo := interpreter.NewLoaderInfo(host.FileID(0), elfRef)
	rm := remotememory.NewProcessVirtualMemory(goPID)

	gData, err := gointerp.Loader(nil, loaderInfo)
	require.NoError(t, err)

	gInstance, err := gData.Attach(nil, goPID, 0x0, rm)
	require.NoError(t, err)

	frameCache, err := lru.New[frameCacheKey, libpf.Frames](frameCacheSize, hashFrameCacheKey)
	require.NoError(t, err)
	frameCache.SetLifetime(frameCacheLifetime)

	var traces []*libpf.Trace
	cr := traceReporterFunc(func(trace *libpf.Trace, _ *samples.TraceEventMeta) error {
		traces = append(traces, trace)
		return nil
	})

	pm := ProcessManager{
		interpreters: map[libpf.PID]map[util.OnDiskFileIdentifier]interpreter.Instance{
			goPID: {
				util.OnDiskFileIdentifier{}: gInstance,
			},
			cPID: {},
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
		return &libpf.EbpfTrace{PID: pid, FrameData: ef, NumFrames: 1}
	}

	pm.HandleTrace(makeTrace(goPID))
	pm.HandleTrace(makeTrace(cPID))

	require.Len(t, traces, 2)

	goFrame := traces[0].Frames[0].Value()
	assert.Equal(t, libpf.GoFrame, goFrame.Type)
	assert.Equal(t, expectedFuncName, goFrame.FunctionName.String())

	cFrame := traces[1].Frames[0].Value()
	assert.Equal(t, libpf.NativeFrame, cFrame.Type)
	assert.Equal(t, "", cFrame.FunctionName.String())
}
