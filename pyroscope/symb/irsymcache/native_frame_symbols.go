package irsymcache // import "go.opentelemetry.io/ebpf-profiler/pyroscope/symb/irsymcache"

import (
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/ebpf-profiler/host"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
)

func SymbolizeNativeFrame(
	resolver samples.NativeSymbolResolver,

	mappingName libpf.String,
	frame host.Frame,
	symbolize func(si samples.SourceInfo),
) {
	fileID := frame.File
	addr := frame.Lineno

	var (
		si  samples.SourceInfo
		err error
	)
	if mappingName != process.VdsoPathName {
		si, err = resolver.ResolveAddress(fileID, uint64(addr))
		if err != nil {
			logrus.Debugf("Failed to symbolize %v %x %v", fileID.StringNoQuotes(), addr, err)
		}
	}
	symbolize(si)
}
