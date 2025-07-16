//go:build !linux

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package remotememory // import "go.opentelemetry.io/ebpf-profiler/remotememory"
import (
	"fmt"
	"runtime"
)

func (vm ProcessVirtualMemory) ReadAt(_ []byte, _ int64) (int, error) {
	return 0, fmt.Errorf("unsupported os %s", runtime.GOOS)
}
