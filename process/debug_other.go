//go:build !linux

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package process // import "go.opentelemetry.io/ebpf-profiler/process"
import (
	"fmt"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"runtime"
)

func NewPtrace(pid libpf.PID) (Process, error) {
	return nil, fmt.Errorf("unsupported os %s", runtime.GOOS)
}
