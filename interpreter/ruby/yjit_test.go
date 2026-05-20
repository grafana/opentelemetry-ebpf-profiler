// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ruby // import "go.opentelemetry.io/ebpf-profiler/interpreter/ruby"

import (
	"debug/elf"
	"testing"

	"go.opentelemetry.io/ebpf-profiler/process"

	"github.com/stretchr/testify/assert"
)

func TestYjitRegionSize(t *testing.T) {
	mib := uint64(1024 * 1024)

	tests := []struct {
		name        string
		version     uint32
		execMemSize uint64
		memSize     uint64
		expected    uint64
	}{
		{
			name:     "ruby_3.2_returns_zero",
			version:  rubyVersion(3, 2, 0),
			expected: 0,
		},
		{
			name:     "ruby_3.3_default_48MiB",
			version:  rubyVersion(3, 3, 0),
			expected: 48 * mib,
		},
		{
			name:        "ruby_3.3_exec_mem_size_override",
			version:     rubyVersion(3, 3, 4),
			execMemSize: 64,
			expected:    64 * mib,
		},
		{
			name:     "ruby_3.4_default_128MiB",
			version:  rubyVersion(3, 4, 0),
			expected: 128 * mib,
		},
		{
			name:     "ruby_3.4_mem_size_override",
			version:  rubyVersion(3, 4, 1),
			memSize:  256,
			expected: 256 * mib,
		},
		{
			name:        "ruby_3.4_exec_mem_size_override",
			version:     rubyVersion(3, 4, 1),
			execMemSize: 64,
			expected:    64 * mib,
		},
		{
			name:        "ruby_3.4_exec_mem_size_overrides_mem_size",
			version:     rubyVersion(3, 4, 1),
			execMemSize: 64,
			memSize:     256,
			expected:    64 * mib,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := yjitRegionSize(tt.version, tt.execMemSize, tt.memSize)
			assert.Equal(t, tt.expected, got)
		})
	}
}

const rx = elf.PF_R | elf.PF_X

func TestFindYJITRegion(t *testing.T) {
	const mib = uint64(1024 * 1024)

	tests := []struct {
		name         string
		mappings     []process.RawMapping
		expectedSize uint64
		wantStart    uint64
		wantFound    bool
	}{
		{
			name: "ruby33_two_rx_anon_pages",
			mappings: []process.RawMapping{
				{Vaddr: 0x7fa73a2ea000, Length: 0x2000, Flags: rx, Path: "[vdso]"},
				{Vaddr: 0x7fa73a2ec000, Length: 0x2a000, Flags: rx, Path: "/usr/lib64/ld-linux-x86-64.so.2"},
				{Vaddr: 0x7fa73a358000, Length: 0x11b000, Flags: rx, Path: ""},
				{Vaddr: 0x7fa73a473000, Length: 0xd5000, Flags: rx, Path: ""},
			},
			expectedSize: 48 * mib,
			wantStart:    0x7fa73a358000,
			wantFound:    true,
		},
		{
			name: "one_rx_anon_gap_then_file_rx",
			mappings: []process.RawMapping{
				{Vaddr: 0x1000000, Length: 0x1000, Flags: rx, Path: ""},
				{Vaddr: 0x1002000, Length: 0x1000, Flags: rx, Path: "/usr/lib/libc.so"},
			},
			expectedSize: 48 * mib,
			wantFound:    false,
		},
		{
			name: "two_anon_groups_with_hole",
			mappings: []process.RawMapping{
				{Vaddr: 0x1000000, Length: 4 * 0x1000, Flags: rx, Path: ""},
				{Vaddr: 0x1000000 + 8*0x1000, Length: 4 * 0x1000, Flags: rx, Path: ""},
			},
			expectedSize: 48 * mib,
			wantStart:    0x1000000,
			wantFound:    true,
		},
		{
			name: "two_anon_groups_hole_larger_than_expected",
			mappings: []process.RawMapping{
				{Vaddr: 0x1000000, Length: 4 * 0x1000, Flags: rx, Path: ""},
				{Vaddr: 0x1000000 + 49*mib, Length: 4 * 0x1000, Flags: rx, Path: ""},
			},
			expectedSize: 48 * mib,
			wantFound:    false,
		},
		{
			name: "file_rx_within_expected_range",
			mappings: []process.RawMapping{
				{Vaddr: 0x1000000, Length: 4 * 0x1000, Flags: rx, Path: ""},
				{Vaddr: 0x1000000 + 4*0x1000, Length: 0x1000, Flags: rx, Path: "/usr/lib/libc.so"},
				{Vaddr: 0x1000000 + 8*0x1000, Length: 4 * 0x1000, Flags: rx, Path: ""},
			},
			expectedSize: 48 * mib,
			wantFound:    false,
		},
		{
			name: "single_anon_rx_mapping",
			mappings: []process.RawMapping{
				{Vaddr: 0x1000000, Length: 4 * 0x1000, Flags: rx, Path: ""},
			},
			expectedSize: 48 * mib,
			wantStart:    0x1000000,
			wantFound:    true,
		},
		{
			name: "part of real process with rw mappings",
			mappings: []process.RawMapping{
				{Vaddr: 0x400000, Length: 0x1000, Flags: 0x5, Path: "/opt/ruby-3.3.10/bin/ruby"},
				{Vaddr: 0x401000, Length: 0x1000, Flags: 0x4, Path: "/opt/ruby-3.3.10/bin/ruby"},
				{Vaddr: 0x402000, Length: 0x1000, Flags: 0x4, Path: "/opt/ruby-3.3.10/bin/ruby"},
				{Vaddr: 0x403000, Length: 0x1000, Flags: 0x6, Path: "/opt/ruby-3.3.10/bin/ruby"},
				{Vaddr: 0x7fa6f0000000, Length: 0x48000, Flags: 0x6, Path: ""},
				{Vaddr: 0x7fa739c00000, Length: 0x410000, Flags: 0x5, Path: "/opt/ruby-3.3.10/lib/libruby.so.3.3.10"},
				{Vaddr: 0x7fa73a010000, Length: 0x1cf000, Flags: 0x4, Path: "/opt/ruby-3.3.10/lib/libruby.so.3.3.10"},
				{Vaddr: 0x7fa73a1df000, Length: 0x16000, Flags: 0x4, Path: "/opt/ruby-3.3.10/lib/libruby.so.3.3.10"},
				{Vaddr: 0x7fa73a1f5000, Length: 0x5000, Flags: 0x6, Path: "/opt/ruby-3.3.10/lib/libruby.so.3.3.10"},
				{Vaddr: 0x7fa73a1fa000, Length: 0x15000, Flags: 0x6, Path: ""},
				{Vaddr: 0x7fa73a2e2000, Length: 0x2000, Flags: 0x6, Path: ""},
				{Vaddr: 0x7fa73a2ea000, Length: 0x2000, Flags: 0x5, Path: "linux-vdso.1.so"},
				{Vaddr: 0x7fa73a2ec000, Length: 0x2a000, Flags: 0x5, Path: "/usr/lib64/ld-linux-x86-64.so.2"},
				{Vaddr: 0x7fa73a316000, Length: 0xc000, Flags: 0x4, Path: "/usr/lib64/ld-linux-x86-64.so.2"},
				{Vaddr: 0x7fa73a322000, Length: 0x2000, Flags: 0x4, Path: "/usr/lib64/ld-linux-x86-64.so.2"},
				{Vaddr: 0x7fa73a324000, Length: 0x1000, Flags: 0x6, Path: "/usr/lib64/ld-linux-x86-64.so.2"},
				{Vaddr: 0x7fa73a325000, Length: 0x1000, Flags: 0x6, Path: ""},
				{Vaddr: 0x7fa73a358000, Length: 0x11b000, Flags: 0x5, Path: ""},
				{Vaddr: 0x7fa73a473000, Length: 0xd8000, Flags: 0x5, Path: ""},
			},
			expectedSize: 48 * mib,
			wantStart:    0x7fa73a358000,
			wantFound:    true,
		},
		{
			name: "16k_rx_hole_then_50mib_rx_expected_none",
			mappings: []process.RawMapping{
				{Vaddr: 0x1000000, Length: 4 * 0x1000, Flags: rx, Path: ""},
				{Vaddr: 0x1000000 + 8*0x1000, Length: 50 * mib, Flags: rx, Path: ""},
			},
			expectedSize: 48 * mib,
			wantFound:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			start, found := findYJITRegion(tt.mappings, tt.expectedSize)
			assert.Equal(t, tt.wantFound, found)
			if found {
				assert.Equal(t, tt.wantStart, start)
			}
		})
	}
}
