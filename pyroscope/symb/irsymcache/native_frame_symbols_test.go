package irsymcache

import (
	"testing"

	"github.com/grafana/pyroscope/lidia"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/host"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
)

func TestNativeFrameSymbols(t *testing.T) {
	resolver, err := NewFSCache(TableTableFactory{
		Options: []lidia.Option{lidia.WithLines(), lidia.WithFiles()},
	}, Options{
		SizeEntries: 1024,
		Path:        t.TempDir(),
	})
	require.NoError(t, err)

	reference := testElfRef(testLibcFIle)
	fid := host.FileID(1)
	err = resolver.ObserveExecutable(fid, reference)
	require.NoError(t, err)
	res := samples.SourceInfo{}
	frame := host.Frame{
		File:          fid,
		Lineno:        libpf.AddressOrLineno(0x9bc7e),
		Type:          0,
		ReturnAddress: false,
	}
	SymbolizeNativeFrame(resolver, libpf.Intern("testmapping"),
		frame,
		func(si samples.SourceInfo) {
			res = si
		})
	require.Equal(t, samples.SourceInfo{
		FunctionName: libpf.Intern("__GI___pthread_cond_timedwait"),
	}, res)
}
