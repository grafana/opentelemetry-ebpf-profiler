//go:build !linux

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package rlimit // import "go.opentelemetry.io/ebpf-profiler/rlimit"

import (
	"fmt"
	"runtime"
)

// todo comment
func MaximizeMemlock() (func(), error) {
	return func() {}, fmt.Errorf("unsupported os %s", runtime.GOOS)
}
