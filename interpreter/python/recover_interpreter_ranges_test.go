//nolint:lll
package python

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/nativeunwind/elfunwindinfo"
	"go.opentelemetry.io/ebpf-profiler/nativeunwind/stackdeltatypes"
	"go.opentelemetry.io/ebpf-profiler/util"
)

func TestDecodeInterpreterKnown(t *testing.T) {
	skipRecoverTest(t)
	testdata := []struct {
		elf      extractor
		expected []util.Range
	}{
		{
			elf: storeExtractor{NewVersion(3, 12), "497dd0d2b4a80bfd11339306c84aa752d811f612a398cb526a0a9ac2f426c0b8"},
			expected: []util.Range{
				{Start: 559770, End: 616313},
				{Start: 1513344, End: 1513706},
			},
		},
		{
			elf: storeExtractor{NewVersion(3, 11), "11ce00a6490d5e4ef941e1f51faaddf40c088a1376f028cbc001985b779397ce"},
			expected: []util.Range{
				{Start: 0x325C10, End: 0x331E54},
			},
		},
		{
			elf: storeExtractor{NewVersion(3, 12), "1a2eb220c22ae7ba8aaf8b243e57dbc25542f8c9c269ed6100c7ad5aea7c3ada"},
			expected: []util.Range{
				{Start: 0x10BABF, End: 0x10BAC7},
				{Start: 0x10C0E0, End: 0x11867a},
			},
		},
		{
			elf: storeExtractor{NewVersion(3, 10), "abc9170dfb10b8a926d2376de94aa9a0ffd7b0ea4febf80606b4bba6c5ffa386"},
			expected: []util.Range{
				{Start: 0x7a796, End: 0x7df87},
				{Start: 0x1726e0, End: 0x17b3de},
			},
		},
		{
			elf: storeExtractor{NewVersion(3, 13), "67997ac257675599247dc0445f4d2705f67e203678fb9920162bc2cd7f9d0009"},
			expected: []util.Range{
				{Start: 0x1f47a0, End: 0x2013ff},
			},
		},
		{
			elf: storeExtractor{NewVersion(3, 11), "b14a0e943b0480bd6d590fa0b2b2734763b3e134625e84ab1c363bb2f77e0a2a"},
			expected: []util.Range{
				{Start: 0xFA0AC, End: 0xFA0AC + 0x24F7},
				{Start: 0x1bed10, End: 0x1c922b},
			},
		},
		{
			elf:      python("python@sha256:f5296959d0d76e7ed9cc507d21dfc6d04532b28c4a8d3a9385adf514b22b552f", "3.13-alpine3.22", NewVersion(3, 13)),
			expected: []util.Range{{Start: 0x2d5190, End: 0x2e6d33}},
		},
		{

			elf: python("python@sha256:af87513194f00b2e6f037eb9a65e339ebbb6f7c6430c456049a7f3169412948f", "3.12-alpine3.22", NewVersion(3, 12)),
			expected: []util.Range{
				// {Start: 0x108AC7, End: 0x108AD0},// opcode 0 - TODO exclude
				{Start: 0x365a60, End: 0x375907},
			},
		},
		{
			elf: python("python@sha256:f31932e5d2bfacfc4b0b26e53189822939641bbd213eaf21181aa13bb1c9c75d", "3.11-alpine3.22", NewVersion(3, 11)),
			expected: []util.Range{
				// {0xF9879, 0xF9880},  // opcode 0 - TODO exclude
				{Start: 0x30cd00, End: 0x319479},
			},
		},
		{
			elf: python("python@sha256:f13869804fc9f1e8e6a55f79b16a21b402252c72cfe55dc6a8db00429614c92d", "3.10-alpine3.22", NewVersion(3, 10)),
			expected: []util.Range{
				{Start: 0x2111b0, End: 0x21aa92},
			},
		},
		{
			elf: python("python@sha256:091f21ccc2f4d319f220582c4e33801e99029f788d5767f74c8cff5396cf4fa5", "3.13-bookworm", NewVersion(3, 13)),
			expected: []util.Range{
				{Start: 0x951CB, End: 0x951D4 + 0x6157},
				{Start: 0x1951e0, End: 0x1a1c1b},
			},
		},
		{
			elf: python("python@sha256:8191c572cf979a5dbc7345474ed93d96c56a6ac95c1dae2451132fe1ba633ae3", "3.12-bookworm", NewVersion(3, 12)),
			expected: []util.Range{
				{Start: 0x112B27, End: 0x1222D2},
				{Start: 0x1ffd80, End: 0x1ffee1},
			},
		},
		{
			elf: python("python@sha256:1c8a588efa1aa943f6692604687aaddf440496fe8ebb6f630b8f0b039b586de0", "3.11-bookworm", NewVersion(3, 11)),
			expected: []util.Range{
				{Start: 0xFE11E, End: 0xFE14C + 0x246C},
				{Start: 0x1bd2b0, End: 0x1c71aa},
			},
		},
		{
			elf: python("python@sha256:6f387d98c66ae06298cdbc19f937cbf375850fb348ae15d9f39f77c8e4d8ad3a", "3.10-bookworm", NewVersion(3, 10)),
			expected: []util.Range{
				{Start: 0x674a9, End: 0x674C7 + 0x18ED},
				{Start: 0x11b6e0, End: 0x1224fe},
			},
		},
		{
			elf: python("python@sha256:5cc3361b5df0f3af709d5bb6c387361d9b2262ea4155dae6c701a2f66eb73b67", "3.13-slim-bookworm", NewVersion(3, 13)),
			expected: []util.Range{
				{Start: 0x95190, End: 0x95190 + 0x6168},
				{Start: 0x1951a0, End: 0x1a1c77},
			},
		},
		{
			elf: python("python@sha256:97983fa8cc88343512862c62307159a82261c3528dc025f79e5a3f7af43e50b4", "3.12-slim-bookworm", NewVersion(3, 12)),
			expected: []util.Range{
				{Start: 0x1ffc30, End: 0x1ffd91},
				{Start: 0x112B79, End: 0x112B79 + 0xF7A7},
			},
		},
		{
			elf: python("python@sha256:df52c7d12cc5bd9b0437abbf295ef7eb78f68948e906d68cec8741a585bb6df3", "3.11-slim-bookworm", NewVersion(3, 11)),
			expected: []util.Range{
				{Start: 0x1bd450, End: 0x1c7358},
				{Start: 0xFE0F7, End: 0xFE0F7 + 0x2491},
			},
		},
		{
			elf: python("python@sha256:ac71103cf5137882806aad2d7ece409bbfe86c075e7478752d36ea073b0934d7", "3.10-slim-bookworm", NewVersion(3, 10)),
			expected: []util.Range{
				{Start: 0x11b730, End: 0x1224e2},
				{Start: 0x6754A, End: 0x6754A + 0x190F},
			},
		},
		{
			elf: python("python@sha256:002de9892d4c0a06486086a261f1d69841f0d2b212dc2799984d08ab028ba3c2", "3.13-slim-bullseye", NewVersion(3, 13)),
			expected: []util.Range{
				{Start: 0x949FB, End: 0x949FB + 0x6354},
				{Start: 0x193e20, End: 0x1a13ea},
			},
		},
		{
			elf: python("python@sha256:3d92a5560ebe1f1992dc8dfffddcb53996c41337eb9a1c3632a206fcd767e4a1", "3.12-slim-bullseye", NewVersion(3, 12)),
			expected: []util.Range{
				{Start: 0x111EDE, End: 0x111EDE + 0x48D2},
				{Start: 0x1f52b0, End: 0x2014d3},
			},
		},
		{
			elf: python("python@sha256:ef5bda33991f10d7f4cc585e8aa9f793bb7c62446d56cc0882a8ce4e59cd8adc", "3.11-slim-bullseye", NewVersion(3, 11)),
			expected: []util.Range{
				{Start: 0x1c0ab0, End: 0x1cbdf9},
				{Start: 0xFE01C, End: 0xFE01C + 0x3513},
			},
		},
		{
			elf: python("python@sha256:474659d6f8839900ffe80e8422f36f68a22ed667460c5e16a4fe5963df84cbd5", "3.10-slim-bullseye", NewVersion(3, 10)),
			expected: []util.Range{
				{Start: 0x11d730, End: 0x125073},
				{Start: 0x6672A, End: 0x6672A + 0x207D},
			},
		},
	}
	for _, td := range testdata {
		t.Run(td.elf.id(), func(t *testing.T) {
			pythonRef, _ := td.elf.extract(t)
			pythonElf, err := pythonRef.GetELF()
			require.NoError(t, err)

			hot, err := pythonElf.LookupSymbol("_PyEval_EvalFrameDefault")
			require.NoError(t, err)

			check(t, hot, pythonRef, td.expected)
		})
	}
}

func check(t *testing.T, hot *libpf.Symbol, pythonRef *pfelf.Reference, expected []util.Range) {
	t.Logf("hot  0x%x - 0x%x", hot.AsRange().Start, hot.AsRange().End)

	pythonElf, err := pythonRef.GetELF()
	require.NoError(t, err)

	cold, err := FindJumpToColdRange(pythonElf, hot.AsRange())
	require.NoError(t, err)
	actual := []util.Range{hot.AsRange()}
	if cold != 0 {
		d := &stackdeltatypes.IntervalData{}
		err = elfunwindinfo.ExtractELF(pythonRef, d,
			elfunwindinfo.WithCaptureFDE(uintptr(cold)))
		require.NoError(t, err)
		actual = append(actual, d.CapturedFDE...)
		sortRanges(actual)
	}

	for _, u := range actual {
		t.Logf("actual {0x%x, 0x%x}", u.Start, u.End)
	}
	sortRanges(expected)
	assert.Equal(t, expected, actual)
}

func TestDecodeInterpreterCompareDebug(t *testing.T) {
	skipRecoverTest(t)
	testdata := []dockerPythonExtractor{
		alpine("alpine:latest", NewVersion(3, 12)),
		alpine("alpine:3.22.0", NewVersion(3, 12)),
		alpine("alpine:3.21.3", NewVersion(3, 12)),
		alpine("alpine:3.21.2", NewVersion(3, 12)),
		alpine("alpine:3.21.1", NewVersion(3, 12)),
		alpine("alpine:3.21.0", NewVersion(3, 12)),
		alpine("alpine:3.20.6", NewVersion(3, 12)),
		alpine("alpine:3.20.5", NewVersion(3, 12)),
		alpine("alpine:3.20.4", NewVersion(3, 12)),
		alpine("alpine:3.20.3", NewVersion(3, 12)),
		alpine("alpine:3.20.2", NewVersion(3, 12)),
		alpine("alpine:3.20.1", NewVersion(3, 12)),
		alpine("alpine:3.20.0", NewVersion(3, 12)),
		alpine("alpine:3.19.7", NewVersion(3, 11)),
		alpine("alpine:3.19.6", NewVersion(3, 11)),
		alpine("alpine:3.19.5", NewVersion(3, 11)),
		alpine("alpine:3.19.4", NewVersion(3, 11)),
		alpine("alpine:3.19.3", NewVersion(3, 11)),
		alpine("alpine:3.19.2", NewVersion(3, 11)),
		alpine("alpine:3.19.1", NewVersion(3, 11)),
		alpine("alpine:3.19.0", NewVersion(3, 11)),
		debian("debian:testing", NewVersion(3, 13)),
		debian("debian:testing-slim", NewVersion(3, 13)),
		debian("debian:trixie", NewVersion(3, 13)),
		debian("debian:trixie-slim", NewVersion(3, 13)),
		debian("debian:12.11", NewVersion(3, 11)),
		debian("debian:12.11-slim", NewVersion(3, 11)),
		debian("debian:11.11", NewVersion(3, 9)),
		debian("debian:11.11-slim", NewVersion(3, 9)),
		debian("ubuntu:25.10", NewVersion(3, 13)),
		debian("ubuntu:25.04", NewVersion(3, 13)),
		debian("ubuntu:24.10", NewVersion(3, 12)),
		debian("ubuntu:24.04", NewVersion(3, 12)),
		debian("ubuntu:22.04", NewVersion(3, 10)),
		debian("ubuntu:20.04", NewVersion(3, 8)),
		python("python:3.13-bookworm", "", NewVersion(3, 13)),
		python("python:3.13.3-bookworm", "", NewVersion(3, 13)),
		python("python:3.13.2-bookworm", "", NewVersion(3, 13)),
		python("python:3.13.1-bookworm", "", NewVersion(3, 13)),
		python("python:3.13.0-bookworm", "", NewVersion(3, 13)),

		python("python:3.12-bookworm", "", NewVersion(3, 12)),
		python("python:3.12.10-bookworm", "", NewVersion(3, 12)),
		python("python:3.12.9-bookworm", "", NewVersion(3, 12)),
		python("python:3.12.8-bookworm", "", NewVersion(3, 12)),
		python("python:3.12.7-bookworm", "", NewVersion(3, 12)),
		python("python:3.12.6-bookworm", "", NewVersion(3, 12)),
		python("python:3.12.5-bookworm", "", NewVersion(3, 12)),
		python("python:3.12.4-bookworm", "", NewVersion(3, 12)),
		python("python:3.12.3-bookworm", "", NewVersion(3, 12)),
		python("python:3.12.2-bookworm", "", NewVersion(3, 12)),
		python("python:3.12.1-bookworm", "", NewVersion(3, 12)),
		python("python:3.12.0-bookworm", "", NewVersion(3, 12)),

		python("python:3.11-bookworm", "", NewVersion(3, 11)),
		python("python:3.11.12-bookworm", "", NewVersion(3, 11)),
		python("python:3.11.11-bookworm", "", NewVersion(3, 11)),
		python("python:3.11.10-bookworm", "", NewVersion(3, 11)),
		python("python:3.11.9-bookworm", "", NewVersion(3, 11)),
		python("python:3.11.8-bookworm", "", NewVersion(3, 11)),
		python("python:3.11.7-bookworm", "", NewVersion(3, 11)),
		python("python:3.11.6-bookworm", "", NewVersion(3, 11)),
		python("python:3.11.5-bookworm", "", NewVersion(3, 11)),
		python("python:3.11.4-bookworm", "", NewVersion(3, 11)),

		python("python:3.10-bookworm", "", NewVersion(3, 10)),
		python("python:3.10.17-bookworm", "", NewVersion(3, 10)),
		python("python:3.10.16-bookworm", "", NewVersion(3, 10)),
		python("python:3.10.15-bookworm", "", NewVersion(3, 10)),
		python("python:3.10.14-bookworm", "", NewVersion(3, 10)),
		python("python:3.10.13-bookworm", "", NewVersion(3, 10)),
		python("python:3.10.12-bookworm", "", NewVersion(3, 10)),

		python("python:3.13-bullseye", "", NewVersion(3, 13)),
		python("python:3.13.3-bullseye", "", NewVersion(3, 13)),
		python("python:3.13.2-bullseye", "", NewVersion(3, 13)),
		python("python:3.13.1-bullseye", "", NewVersion(3, 13)),
		python("python:3.13.0-bullseye", "", NewVersion(3, 13)),

		python("python:3.12-bullseye", "", NewVersion(3, 12)),
		python("python:3.12.10-bullseye", "", NewVersion(3, 12)),
		python("python:3.12.9-bullseye", "", NewVersion(3, 12)),
		python("python:3.12.8-bullseye", "", NewVersion(3, 12)),
		python("python:3.12.7-bullseye", "", NewVersion(3, 12)),
		python("python:3.12.6-bullseye", "", NewVersion(3, 12)),
		python("python:3.12.5-bullseye", "", NewVersion(3, 12)),
		python("python:3.12.4-bullseye", "", NewVersion(3, 12)),
		python("python:3.12.3-bullseye", "", NewVersion(3, 12)),
		python("python:3.12.2-bullseye", "", NewVersion(3, 12)),
		python("python:3.12.1-bullseye", "", NewVersion(3, 12)),
		python("python:3.12.0-bullseye", "", NewVersion(3, 12)),

		python("python:3.11-bullseye", "", NewVersion(3, 11)),
		python("python:3.11.12-bullseye", "", NewVersion(3, 11)),
		python("python:3.11.11-bullseye", "", NewVersion(3, 11)),
		python("python:3.11.10-bullseye", "", NewVersion(3, 11)),
		python("python:3.11.9-bullseye", "", NewVersion(3, 11)),
		python("python:3.11.8-bullseye", "", NewVersion(3, 11)),
		python("python:3.11.7-bullseye", "", NewVersion(3, 11)),
		python("python:3.11.6-bullseye", "", NewVersion(3, 11)),
		python("python:3.11.5-bullseye", "", NewVersion(3, 11)),
		python("python:3.11.4-bullseye", "", NewVersion(3, 11)),
		python("python:3.11.3-bullseye", "", NewVersion(3, 11)),
		python("python:3.11.2-bullseye", "", NewVersion(3, 11)),
		python("python:3.11.1-bullseye", "", NewVersion(3, 11)),
		python("python:3.11.0-bullseye", "", NewVersion(3, 11)),

		python("python:3.10-bullseye", "", NewVersion(3, 10)),
		python("python:3.10.18-bullseye", "", NewVersion(3, 10)),
		python("python:3.10.17-bullseye", "", NewVersion(3, 10)),
		python("python:3.10.16-bullseye", "", NewVersion(3, 10)),
		python("python:3.10.15-bullseye", "", NewVersion(3, 10)),
		python("python:3.10.14-bullseye", "", NewVersion(3, 10)),
		python("python:3.10.13-bullseye", "", NewVersion(3, 10)),
		python("python:3.10.12-bullseye", "", NewVersion(3, 10)),
		python("python:3.10.11-bullseye", "", NewVersion(3, 10)),
		python("python:3.10.10-bullseye", "", NewVersion(3, 10)),
		python("python:3.10.9-bullseye", "", NewVersion(3, 10)),
	}
	for _, td := range testdata {
		t.Run(td.name, func(t *testing.T) {
			elfRef, debugElfRef := td.extract(t)
			require.NotNil(t, debugElfRef)

			elf, err := elfRef.GetELF()
			require.NoError(t, err)

			debugElf, err := debugElfRef.GetELF()
			require.NoError(t, err)

			debugSymbols, err := debugElf.ReadSymbols()
			require.NoError(t, err)

			cold, err := debugSymbols.LookupSymbol("_PyEval_EvalFrameDefault.cold")
			require.NoError(t, err)

			t.Logf("cold 0x%x - 0x%x", cold.AsRange().Start, cold.AsRange().End)

			hot, err := elf.LookupSymbol("_PyEval_EvalFrameDefault")
			require.NoError(t, err)

			expected := []util.Range{hot.AsRange(), cold.AsRange()}
			check(t, hot, elfRef, expected)
		})
	}
}

func skipRecoverTest(t *testing.T) {
	if runtime.GOARCH != "amd64" || runtime.GOOS != "linux" {
		t.Skip("only amd64 linux needed")
	}
}
