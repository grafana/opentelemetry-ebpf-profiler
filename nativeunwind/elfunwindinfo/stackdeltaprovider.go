// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package elfunwindinfo // import "go.opentelemetry.io/ebpf-profiler/nativeunwind/elfunwindinfo"

import (
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"os"
	"sync/atomic"
	"unsafe"

	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/nativeunwind"
	sdtypes "go.opentelemetry.io/ebpf-profiler/nativeunwind/stackdeltatypes"
)

// ELFStackDeltaProvider extracts stack deltas from ELF executables available
// via the pfelf.File interface.
type ELFStackDeltaProvider struct {
	// Metrics
	successCount         atomic.Uint64
	extractionErrorCount atomic.Uint64

	opts             []ExtractOption
	elfFileSizeLimit int
}

// Compile time check that the ELFStackDeltaProvider implements its interface correctly.
var _ nativeunwind.StackDeltaProvider = (*ELFStackDeltaProvider)(nil)

// NewStackDeltaProvider creates a stack delta provider using the ELF eh_frame extraction.
func NewStackDeltaProvider(opts ...ExtractOption) nativeunwind.StackDeltaProvider {
	return &ELFStackDeltaProvider{
		opts: opts,
	}
}

// GetIntervalStructuresForFile builds the stack delta information for a single executable.
func (provider *ELFStackDeltaProvider) GetIntervalStructuresForFile(fid host.FileID,
	elfRef *pfelf.Reference, interval *sdtypes.IntervalData) error {
	log.Debugf("Extracting stack deltas from %s sz %d %s ", fid.StringNoQuotes(), elfRef.FileSize(), elfRef.FileName())
	err := ExtractELF(elfRef, interval, provider.opts...)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			provider.extractionErrorCount.Add(1)
		}
		return fmt.Errorf("failed to extract stack deltas from %s: %w",
			elfRef.FileName(), err)
	}
	sz := len(interval.Deltas) * int(unsafe.Sizeof(sdtypes.IntervalData{}))
	log.Debugf("Successfully extracted stack deltas from %s %s count: %d size: %d", fid.StringNoQuotes(), elfRef.FileName(), len(interval.Deltas), sz)

	provider.successCount.Add(1)
	return nil
}

func (provider *ELFStackDeltaProvider) GetAndResetStatistics() nativeunwind.Statistics {
	return nativeunwind.Statistics{
		Success:          provider.successCount.Swap(0),
		ExtractionErrors: provider.extractionErrorCount.Swap(0),
	}
}
