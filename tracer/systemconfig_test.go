// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracer

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf/btf"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/support"
)

func TestValidateSystemAnalysisResult(t *testing.T) {
	address := libpf.SymbolValue(0x1234)

	t.Run("not handled", func(t *testing.T) {
		err := validateSystemAnalysisResult(support.SystemAnalysis{Pid: 77}, address)
		require.Error(t, err)
		require.ErrorIs(t, err, errSystemAnalysisNotHandled)
		require.ErrorContains(t, err, "pid 77")
	})

	t.Run("helper failure", func(t *testing.T) {
		err := validateSystemAnalysisResult(support.SystemAnalysis{Err: -14}, address)
		require.Error(t, err)
		require.True(t, errors.Is(err, errSystemAnalysisFailed))
		require.ErrorContains(t, err, "helper err=-14")
	})

	t.Run("success", func(t *testing.T) {
		err := validateSystemAnalysisResult(support.SystemAnalysis{}, address)
		require.NoError(t, err)
	})
}

func TestCalculateFieldOffsetFindsAnonymousCompositeMembers(t *testing.T) {
	u64Type := &btf.Int{Name: "u64", Size: 8}
	vmArea := &btf.Struct{
		Name: "vm_area_struct",
		Size: 64,
		Members: []btf.Member{
			{
				Name:   "vm_start",
				Type:   u64Type,
				Offset: btf.Bits(0),
			},
			{
				Type: &btf.Union{
					Size: 16,
					Members: []btf.Member{
						{
							Type: &btf.Struct{
								Size: 16,
								Members: []btf.Member{
									{
										Name:   "vm_flags",
										Type:   u64Type,
										Offset: btf.Bits(64),
									},
								},
							},
						},
					},
				},
				Offset: btf.Bits(128),
			},
		},
	}

	offset, err := calculateFieldOffset(vmArea, "vm_flags")
	require.NoError(t, err)
	require.Equal(t, uint(24), offset)
}

func TestPythonFramesPerProgram(t *testing.T) {
	tests := map[string]struct {
		goarch string
		major  uint32
		minor  uint32
		want   uint32
	}{
		"5.x default": {
			goarch: "amd64",
			major:  5,
			minor:  15,
			want:   defaultPythonFramesPerProgram,
		},
		"6.5 default": {
			goarch: "amd64",
			major:  6,
			minor:  5,
			want:   defaultPythonFramesPerProgram,
		},
		"6.6 expanded": {
			goarch: "amd64",
			major:  6,
			minor:  6,
			want:   expandedPythonFramesPerProgram,
		},
		"6.16 expanded": {
			goarch: "amd64",
			major:  6,
			minor:  16,
			want:   expandedPythonFramesPerProgram,
		},
		"amd64 6.18 limited": {
			goarch: "amd64",
			major:  6,
			minor:  18,
			want:   limitedPythonFramesPerProgram,
		},
		"amd64 6.19 limited": {
			goarch: "amd64",
			major:  6,
			minor:  19,
			want:   limitedPythonFramesPerProgram,
		},
		"arm64 6.18 default": {
			goarch: "arm64",
			major:  6,
			minor:  18,
			want:   defaultPythonFramesPerProgram,
		},
		"7.x expanded": {
			goarch: "amd64",
			major:  7,
			minor:  1,
			want:   expandedPythonFramesPerProgram,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, tc.want, pythonFramesPerProgramForArch(tc.goarch, tc.major, tc.minor))
		})
	}
}
