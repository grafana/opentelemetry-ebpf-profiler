package irsymcache // import "go.opentelemetry.io/ebpf-profiler/pyroscope/symb/irsymcache"

import (
	"time"

	lru "github.com/elastic/go-freelru"
	"github.com/sirupsen/logrus"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
)

const (
	ExecutableCacheLifetime = 1 * time.Hour
	FramesCacheLifetime     = 1 * time.Hour
	FrameMapLifetime        = 1 * time.Hour
)

func SymbolizeNativeFrame(
	resolver samples.NativeSymbolResolver,
	frames *lru.SyncedLRU[
		libpf.FrameID,
		samples.SourceInfo,
	],
	mappingName libpf.String,
	frameID libpf.FrameID,
	symbolize func(si samples.SourceInfo),
) {
	fileID := frameID.FileID()
	addr := frameID.AddressOrLine()

	if si, exists := frames.GetAndRefresh(frameID, FramesCacheLifetime); exists {
		symbolize(si)
		return
	}

	var (
		si  samples.SourceInfo
		err error
	)
	if mappingName != process.VdsoPathName {
		si, err = resolver.ResolveAddress(fileID, uint64(addr))
		if err != nil {
			logrus.Debugf("Failed to symbolize %v %v", frameID.String(), err)
		}
	}
	frames.Add(frameID, si)
	symbolize(si)
}
