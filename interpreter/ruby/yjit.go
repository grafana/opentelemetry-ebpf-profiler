// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ruby // import "go.opentelemetry.io/ebpf-profiler/interpreter/ruby"

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"go.opentelemetry.io/ebpf-profiler/libpf/pfunsafe"
	"go.opentelemetry.io/ebpf-profiler/process"
)

func parseYJITMemArgs(pr process.Process) (execMemSize, memSize uint64) {
	forEachProcessArg(pr, func(arg string) {
		if v, ok := strings.CutPrefix(arg, "--yjit-exec-mem-size="); ok {
			if n, err := strconv.ParseUint(v, 10, 64); err == nil {
				execMemSize = n
			}
		}
		if v, ok := strings.CutPrefix(arg, "--yjit-mem-size="); ok {
			if n, err := strconv.ParseUint(v, 10, 64); err == nil {
				memSize = n
			}
		}
	})
	return execMemSize, memSize
}

func yjitRegionSize(version uint32, execMemSize, memSize uint64) uint64 {
	major := (version >> 16) & 0xff
	minor := (version >> 8) & 0xff

	if major < 3 || (major == 3 && minor < 3) {
		return 0
	}

	var defaultMiB uint64
	if major == 3 && minor == 3 {
		defaultMiB = 48
	} else {
		defaultMiB = 128
	}

	if major == 3 && minor == 3 {
		if execMemSize > 0 {
			return execMemSize * 1024 * 1024
		}
		return defaultMiB * 1024 * 1024
	}

	if execMemSize > 0 {
		return execMemSize * 1024 * 1024
	}
	if memSize > 0 {
		return memSize * 1024 * 1024
	}
	return defaultMiB * 1024 * 1024
}

func determineYJITRegionSize(version uint32, pr process.Process) uint64 {
	execMemSize, memSize := parseYJITMemArgs(pr)
	return yjitRegionSize(version, execMemSize, memSize)
}

func findYJITRegion(mappings []process.Mapping, expectedSize uint64) (start uint64, found bool) {
	var end uint64
	for i := range mappings {
		m := &mappings[i]
		if !m.IsAnonymous() {
			if found && m.Vaddr < end {
				return 0, false
			}
			continue
		}
		if !found {
			start = m.Vaddr
			end = start + expectedSize
			found = true
			continue
		}
		if m.Vaddr >= end {
			return 0, false
		}
	}
	return start, found
}

func forEachProcessArg(pr process.Process, fn func(string)) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pr.PID()))
	if err != nil || len(data) == 0 {
		return
	}
	for len(data) > 0 {
		i := 0
		for i < len(data) && data[i] != 0 {
			i++
		}
		if i > 0 {
			fn(pfunsafe.ToString(data[:i]))
		}
		data = data[i:]
		if len(data) > 0 {
			data = data[1:]
		}
	}
}

func detectYJITRegion(pr process.Process, version uint32,
	mappings []process.Mapping) (start, end uint64, found bool) {
	expectedSize := determineYJITRegionSize(version, pr)
	if expectedSize == 0 {
		return 0, 0, false
	}

	start, found = findYJITRegion(mappings, expectedSize)
	if !found {
		return 0, 0, false
	}
	return start, start + expectedSize, true
}
