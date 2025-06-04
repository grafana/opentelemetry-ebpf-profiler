package python

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/tools/coredump/modulestore"
	"go.opentelemetry.io/ebpf-profiler/util"
)

const moduleStoreCachePath = "../../tools/coredump/modulecache"

func TestDecodeInterpreterKnown(t *testing.T) {
	testdata := []struct {
		elf      extractor
		expected []util.Range
	}{
		{
			elf: storeExtractor{pythonVer(3, 12), "497dd0d2b4a80bfd11339306c84aa752d811f612a398cb526a0a9ac2f426c0b8"},
			expected: []util.Range{
				{Start: 559770, End: 616313},
				{Start: 1513344, End: 1513706},
			},
		},
		{
			elf: storeExtractor{pythonVer(3, 11), "11ce00a6490d5e4ef941e1f51faaddf40c088a1376f028cbc001985b779397ce"},
			expected: []util.Range{
				{Start: 0x325C10, End: 0x331E54},
			},
		},
		{
			elf: storeExtractor{pythonVer(3, 12), "1a2eb220c22ae7ba8aaf8b243e57dbc25542f8c9c269ed6100c7ad5aea7c3ada"},
			expected: []util.Range{
				{Start: 0x10BABF, End: 0x10BAC7},
				{Start: 0x10C0E0, End: 0x11867a},
			},
		},
		{
			elf: storeExtractor{pythonVer(3, 10), "abc9170dfb10b8a926d2376de94aa9a0ffd7b0ea4febf80606b4bba6c5ffa386"},
			expected: []util.Range{
				{Start: 0x7a796, End: 0x7df87},
				{Start: 0x1726e0, End: 0x17b3de},
			},
		},
		{
			elf: storeExtractor{pythonVer(3, 13), "67997ac257675599247dc0445f4d2705f67e203678fb9920162bc2cd7f9d0009"},
			expected: []util.Range{
				{Start: 0x1f47a0, End: 0x2013ff},
			},
		},
		{
			elf: storeExtractor{pythonVer(3, 11), "b14a0e943b0480bd6d590fa0b2b2734763b3e134625e84ab1c363bb2f77e0a2a"},
			expected: []util.Range{
				{Start: 0xFA0AC, End: 0xFA0AC + 0x24F7},
				{Start: 0x1bed10, End: 0x1c922b},
			},
		},
		{
			elf:      python("python@sha256:f5296959d0d76e7ed9cc507d21dfc6d04532b28c4a8d3a9385adf514b22b552f", "3.13-alpine3.22", pythonVer(3, 13)),
			expected: []util.Range{{Start: 0x2d5190, End: 0x2e6d33}},
		},
		{

			elf: python("python@sha256:af87513194f00b2e6f037eb9a65e339ebbb6f7c6430c456049a7f3169412948f", "3.12-alpine3.22", pythonVer(3, 12)),
			expected: []util.Range{
				//{Start: 0x108AC7, End: 0x108AD0},// opcode 0 - TODO exclude
				{Start: 0x365a60, End: 0x375907},
			},
		},
		{
			elf: python("python@sha256:f31932e5d2bfacfc4b0b26e53189822939641bbd213eaf21181aa13bb1c9c75d", "3.11-alpine3.22", pythonVer(3, 11)),
			expected: []util.Range{
				//{0xF9879, 0xF9880},  // opcode 0 - TODO exclude
				{0x30cd00, 0x319479},
			},
		},
		{
			elf: python("python@sha256:f13869804fc9f1e8e6a55f79b16a21b402252c72cfe55dc6a8db00429614c92d", "3.10-alpine3.22", pythonVer(3, 10)),
			expected: []util.Range{
				{Start: 0x2111b0, End: 0x21aa92},
			},
		},
		{
			elf: python("python@sha256:091f21ccc2f4d319f220582c4e33801e99029f788d5767f74c8cff5396cf4fa5", "3.13-bookworm", pythonVer(3, 13)),
			expected: []util.Range{
				{0x951CB, 0x951D4 + 0x6157},
				{Start: 0x1951e0, End: 0x1a1c1b},
			},
		},
		{
			elf: python("python@sha256:8191c572cf979a5dbc7345474ed93d96c56a6ac95c1dae2451132fe1ba633ae3", "3.12-bookworm", pythonVer(3, 12)),
			expected: []util.Range{
				{Start: 0x112B27, End: 0x1222D2},
				{Start: 0x1ffd80, End: 0x1ffee1},
			},
		},
		{
			elf: python("python@sha256:1c8a588efa1aa943f6692604687aaddf440496fe8ebb6f630b8f0b039b586de0", "3.11-bookworm", pythonVer(3, 11)),
			expected: []util.Range{
				{0xFE11E, 0xFE14C + 0x246C},
				{Start: 0x1bd2b0, End: 0x1c71aa},
			},
		},
		{
			elf: python("python@sha256:6f387d98c66ae06298cdbc19f937cbf375850fb348ae15d9f39f77c8e4d8ad3a", "3.10-bookworm", pythonVer(3, 10)),
			expected: []util.Range{
				{Start: 0x674a9, End: 0x674C7 + 0x18ED},
				{Start: 0x11b6e0, End: 0x1224fe},
			},
		},
		{
			elf: python("python@sha256:5cc3361b5df0f3af709d5bb6c387361d9b2262ea4155dae6c701a2f66eb73b67", "3.13-slim-bookworm", pythonVer(3, 13)),
			expected: []util.Range{
				{0x95190, 0x95190 + 0x6168},
				{0x1951a0, 0x1a1c77},
			},
		},
		{
			elf: python("python@sha256:97983fa8cc88343512862c62307159a82261c3528dc025f79e5a3f7af43e50b4", "3.12-slim-bookworm", pythonVer(3, 12)),
			expected: []util.Range{
				{0x1ffc30, 0x1ffd91},
				{0x112B79, 0x112B79 + 0xF7A7},
			},
		},
		{
			elf: python("python@sha256:df52c7d12cc5bd9b0437abbf295ef7eb78f68948e906d68cec8741a585bb6df3", "3.11-slim-bookworm", pythonVer(3, 11)),
			expected: []util.Range{
				{0x1bd450, 0x1c7358},
				{0xFE0F7, 0xFE0F7 + 0x2491},
			},
		},
		{
			elf: python("python@sha256:ac71103cf5137882806aad2d7ece409bbfe86c075e7478752d36ea073b0934d7", "3.10-slim-bookworm", pythonVer(3, 10)),
			expected: []util.Range{
				{0x11b730, 0x1224e2},
				{0x6754A, 0x6754A + 0x190F},
			},
		},
		{
			elf: python("python@sha256:002de9892d4c0a06486086a261f1d69841f0d2b212dc2799984d08ab028ba3c2", "3.13-slim-bullseye", pythonVer(3, 13)),
			expected: []util.Range{
				{0x949FB, 0x949FB + 0x6354},
				{0x193e20, 0x1a13ea},
			},
		},
		{
			elf: python("python@sha256:3d92a5560ebe1f1992dc8dfffddcb53996c41337eb9a1c3632a206fcd767e4a1", "3.12-slim-bullseye", pythonVer(3, 12)),
			expected: []util.Range{
				{0x111EDE, 0x111EDE + 0x48D2},
				{0x1f52b0, 0x2014d3},
			},
		},
		{
			elf: python("python@sha256:ef5bda33991f10d7f4cc585e8aa9f793bb7c62446d56cc0882a8ce4e59cd8adc", "3.11-slim-bullseye", pythonVer(3, 11)),
			expected: []util.Range{
				{0x1c0ab0, 0x1cbdf9},
				{0xFE01C, 0xFE01C + 0x3513},
			},
		},
		{
			elf: python("python@sha256:474659d6f8839900ffe80e8422f36f68a22ed667460c5e16a4fe5963df84cbd5", "3.10-slim-bullseye", pythonVer(3, 10)),
			expected: []util.Range{
				{0x11d730, 0x125073},
				{0x6672A, 0x6672A + 0x207D},
			},
		},
		//todo add alpine 3.21
		//todo add alpine 3.20
	}
	for _, td := range testdata {
		t.Run(td.elf.id(), func(t *testing.T) {
			python, _ := td.elf.extract(t)
			sym, err := python.LookupSymbol("_PyEval_EvalFrameDefault")
			require.NoError(t, err)
			t.Logf("hot at {0x%x, 0x%x}", sym.Address, uint64(sym.Address)+sym.Size)
			start := util.Range{Start: uint64(sym.Address), End: uint64(sym.Address) + sym.Size}
			actual, err := recoverInterpreterRanges(python, start, td.elf.version())
			require.NoError(t, err)
			for _, u := range actual {
				t.Logf("actual {0x%x, 0x%x}", u.Start, u.End)
			}
			sortRanges(td.expected)
			assert.Equal(t, td.expected, actual)

		})
	}
}

func TestDecodeInterpreterCheckNumberOfRangesOnly(t *testing.T) {
	t.Skip("takes too long")
	var es []extractor
	add := func(maj, min, fix int, extraSuffixes []string) {
		//extraSuffixes = append(extraSuffixes, "-bookworm", "-bullseye", "-slim-bookworm", "-slim-bullseye")
		sver := fmt.Sprintf("%d.%d.%d", maj, min, fix)
		v := pythonVer(maj, min)
		for _, suffix := range extraSuffixes {
			es = append(es, python("python:"+sver+suffix, "python:"+sver+suffix, v))
		}
	}
	add(3, 13, 3, []string{"-alpine3.22", "-alpine3.21"})
	add(3, 13, 2, []string{"-alpine3.21", "-alpine3.20"})
	add(3, 13, 1, []string{"-alpine3.21", "-alpine3.20"})
	add(3, 13, 0, []string{"-alpine3.20", "-alpine3.19"})
	add(3, 12, 10, []string{"-alpine3.22", "-alpine3.21"})
	add(3, 12, 9, []string{"-alpine3.21", "-alpine3.20"})
	add(3, 12, 8, []string{"-alpine3.21", "-alpine3.20"})
	add(3, 12, 7, []string{"-alpine3.20", "-alpine3.19"})
	add(3, 12, 6, []string{"-alpine3.20", "-alpine3.19"})
	add(3, 12, 5, []string{"-alpine3.20", "-alpine3.19"})
	add(3, 12, 4, []string{"-alpine3.20", "-alpine3.19"})
	add(3, 12, 3, []string{"-alpine3.20", "-alpine3.19"})
	add(3, 12, 2, []string{"-alpine3.19", "-alpine3.18"})
	add(3, 12, 1, []string{"-alpine3.19", "-alpine3.18"})
	add(3, 12, 0, []string{"-alpine3.18", "-alpine3.17"})
	add(3, 11, 12, []string{"-alpine3.21", "-alpine3.20"})
	add(3, 11, 11, []string{"-alpine3.21", "-alpine3.20"})
	add(3, 11, 10, []string{"-alpine3.20", "-alpine3.19"})
	add(3, 11, 9, []string{"-alpine3.20", "-alpine3.19"})
	add(3, 11, 8, []string{"-alpine3.19", "-alpine3.18"})
	add(3, 11, 7, []string{"-alpine3.19", "-alpine3.18"})
	add(3, 11, 6, []string{"-alpine3.18", "-alpine3.17"})
	add(3, 11, 5, []string{"-alpine3.18", "-alpine3.17"})
	add(3, 11, 4, []string{"-alpine3.18", "-alpine3.17"})
	add(3, 11, 3, []string{"-alpine3.18", "-alpine3.17"})
	add(3, 11, 2, []string{"-alpine3.17", "-alpine3.16"})
	add(3, 11, 1, []string{"-alpine3.17", "-alpine3.16"})
	add(3, 11, 0, []string{"-alpine3.17", "-alpine3.16"})
	add(3, 10, 17, []string{"-alpine3.22", "-alpine3.21"})
	add(3, 10, 16, []string{"-alpine3.21", "-alpine3.20"})
	add(3, 10, 15, []string{"-alpine3.20", "-alpine3.19"})
	add(3, 10, 14, []string{"-alpine3.19", "-alpine3.18"})
	add(3, 10, 13, []string{"-alpine3.19", "-alpine3.18"})
	add(3, 10, 12, []string{"-alpine3.18", "-alpine3.17"})
	add(3, 10, 11, []string{"-alpine3.18", "-alpine3.17"})
	add(3, 10, 10, []string{"-alpine3.17", "-alpine3.16"})
	add(3, 10, 9, []string{"-alpine3.17", "-alpine3.16"})
	add(3, 10, 8, []string{"-alpine3.17", "-alpine3.16"})
	add(3, 10, 7, []string{"-alpine3.16", "-alpine3.15"})
	add(3, 10, 6, []string{"-alpine3.16", "-alpine3.15"})
	add(3, 10, 5, []string{"-alpine3.16", "-alpine3.15"})
	add(3, 10, 4, []string{"-alpine3.16", "-alpine3.15"})
	add(3, 10, 3, []string{"-alpine3.15", "-alpine3.14"})
	add(3, 10, 2, []string{"-alpine3.15", "-alpine3.14"})
	add(3, 10, 1, []string{"-alpine3.15", "-alpine3.14"})
	add(3, 10, 0, []string{"-alpine3.15", "-alpine3.14"})
	for _, e := range es {
		t.Run(e.id(), func(t *testing.T) {
			t1 := time.Now()
			python, _ := e.extract(t)
			t.Logf("extract took %v", time.Since(t1))
			sym, err := python.LookupSymbol("_PyEval_EvalFrameDefault")
			require.NoError(t, err)
			t.Logf("hot at {0x%x, 0x%x}", sym.Address, uint64(sym.Address)+sym.Size)
			start := util.Range{Start: uint64(sym.Address), End: uint64(sym.Address) + sym.Size}
			actual, err := recoverInterpreterRanges(python, start, e.version())
			require.NoError(t, err)
			for _, u := range actual {
				t.Logf("actual {0x%x, 0x%x}", u.Start, u.End)
			}
			require.Contains(t, actual, sym.AsRange())
			require.True(t, len(actual) <= 2)
		})
	}

}

func BenchmarkDecodeInterpreter(b *testing.B) {
	libPython, _ := storeExtractor{pythonVer(3, 11), "497dd0d2b4a80bfd11339306c84aa752d811f612a398cb526a0a9ac2f426c0b8"}.extract(b)
	sym, err := libPython.LookupSymbol("_PyEval_EvalFrameDefault")
	if err != nil {
		b.FailNow()
	}
	defer libPython.Close()
	b.ResetTimer()
	start := util.Range{Start: uint64(sym.Address), End: uint64(sym.Address) + sym.Size}
	for i := 0; i < b.N; i++ {
		ranges, err := recoverInterpreterRanges(libPython, start, 0)
		if err != nil || len(ranges) != 2 {
			b.FailNow()
		}
	}
}

func TestMergeRecoveredRages(t *testing.T) {
	type testcase struct {
		src       util.Range
		recovered []util.Range
		expected  []util.Range
	}
	testcases := []testcase{
		{
			util.Range{Start: 0x1f47a0, End: 0x2013ff},
			[]util.Range{
				{Start: 0x1f47a0, End: 0x1f4a9d},
				{Start: 0x20029f, End: 0x200793},
				{Start: 0x2013d3, End: 0x2013f6},
			},
			[]util.Range{{Start: 0x1f47a0, End: 0x2013ff}},
		},
		{
			util.Range{Start: 10, End: 20},
			[]util.Range{{0, 3},
				{Start: 10, End: 15},
				{Start: 18, End: 19},
				{Start: 30, End: 40}},
			[]util.Range{{0, 3},
				{Start: 10, End: 20},
				{Start: 30, End: 40}},
		},
		{
			src: util.Range{Start: 10, End: 20},
			recovered: []util.Range{{End: 10},
				{Start: 10, End: 15},
				{Start: 18, End: 19},
				{Start: 30, End: 40}},
			expected: []util.Range{{Start: 0, End: 20},
				{Start: 30, End: 40}},
		},
		{
			util.Range{Start: 10, End: 20},
			[]util.Range{{0, 3},
				{Start: 10, End: 15},
				{Start: 18, End: 40}},
			[]util.Range{{0, 3},
				{Start: 10, End: 40}},
		},
	}
	for j, td := range testcases {
		t.Run(fmt.Sprintf("%d", j), func(t *testing.T) {
			res := mergeRecoveredRanges(td.src, td.recovered)
			require.Equal(t, td.expected, res)
		})
	}

}

func TestDecodeInterpreterCompareDebug(t *testing.T) {
	if runtime.GOARCH != "amd64" || runtime.GOOS != "linux" {
		t.Skip("only amd64 linux needed")
	}

	testdata := []dockerPythonExtractor{
		alpine("alpine:latest", pythonVer(3, 12)),
		alpine("alpine:3.22.0", pythonVer(3, 12)),
		alpine("alpine:3.21.3", pythonVer(3, 12)),
		alpine("alpine:3.21.2", pythonVer(3, 12)),
		alpine("alpine:3.21.1", pythonVer(3, 12)),
		alpine("alpine:3.21.0", pythonVer(3, 12)),
		alpine("alpine:3.20.6", pythonVer(3, 12)),
		alpine("alpine:3.20.5", pythonVer(3, 12)),
		alpine("alpine:3.20.4", pythonVer(3, 12)),
		alpine("alpine:3.20.3", pythonVer(3, 12)),
		alpine("alpine:3.20.2", pythonVer(3, 12)),
		alpine("alpine:3.20.1", pythonVer(3, 12)),
		alpine("alpine:3.20.0", pythonVer(3, 12)),
		alpine("alpine:3.19.7", pythonVer(3, 11)),
		alpine("alpine:3.19.6", pythonVer(3, 11)),
		alpine("alpine:3.19.5", pythonVer(3, 11)),
		alpine("alpine:3.19.4", pythonVer(3, 11)),
		alpine("alpine:3.19.3", pythonVer(3, 11)),
		alpine("alpine:3.19.2", pythonVer(3, 11)),
		alpine("alpine:3.19.1", pythonVer(3, 11)),
		alpine("alpine:3.19.0", pythonVer(3, 11)),
		debian("debian:testing", pythonVer(3, 13)),
		debian("debian:testing-slim", pythonVer(3, 13)),
		debian("debian:12.11", pythonVer(3, 11)),
		debian("debian:12.11-slim", pythonVer(3, 11)),
		debian("debian:11.11", pythonVer(3, 9)),
		debian("debian:11.11-slim", pythonVer(3, 9)),
		debian("ubuntu:25.10", pythonVer(3, 13)),
		debian("ubuntu:25.04", pythonVer(3, 13)),
		debian("ubuntu:24.10", pythonVer(3, 12)),
		debian("ubuntu:24.04", pythonVer(3, 12)),
		debian("ubuntu:22.04", pythonVer(3, 10)),
		debian("ubuntu:20.04", pythonVer(3, 8)),
		python("python@sha256:091f21ccc2f4d319f220582c4e33801e99029f788d5767f74c8cff5396cf4fa5", "3.13-bookworm", pythonVer(3, 13)),
		python("python@sha256:8191c572cf979a5dbc7345474ed93d96c56a6ac95c1dae2451132fe1ba633ae3", "3.12-bookworm", pythonVer(3, 12)),
		python("python@sha256:1c8a588efa1aa943f6692604687aaddf440496fe8ebb6f630b8f0b039b586de0", "3.11-bookworm", pythonVer(3, 11)),
		python("python@sha256:6f387d98c66ae06298cdbc19f937cbf375850fb348ae15d9f39f77c8e4d8ad3a", "3.10-bookworm", pythonVer(3, 10)),

		python("python@sha256:845de9a763179bd336f12b6d296a5d016f766b77868d4873d2ac2c01e74e83e9", "3.13-bullseye", pythonVer(3, 13)),
		python("python@sha256:f999fda265134523a8a65089edf0c1d94371c800639844030648f77fabd29493", "3.12-bullseye", pythonVer(3, 12)),
		python("python@sha256:6bc5115724b3acffba620c04ba4b5b490a948e73771e7d3c503688c44e6e1a9b", "3.11-bullseye", pythonVer(3, 11)),
		python("python@sha256:687bc3df0766d7ed96fa136a9b0c09c838e55fdad4c6284a931e55f311ef4e56", "3.10-bullseye", pythonVer(3, 10)),
		//todo no need for hash, add more patch versions
	}
	for _, td := range testdata {
		t.Run(td.name, func(t *testing.T) {
			t.Parallel()
			elf, debugElf := td.extract(t)
			require.NotNil(t, debugElf)

			debugSymbols, err := debugElf.ReadSymbols()
			require.NoError(t, err)
			cold, err := debugSymbols.LookupSymbol("_PyEval_EvalFrameDefault.cold")
			require.NoError(t, err)
			t.Logf("cold 0x%x - 0x%x", cold.AsRange().Start, cold.AsRange().End)

			hot, err := elf.LookupSymbol("_PyEval_EvalFrameDefault")
			require.NoError(t, err)
			t.Logf("hot  0x%x - 0x%x", hot.AsRange().Start, hot.AsRange().End)

			ranges, err := recoverInterpreterRanges(elf, hot.AsRange(), td.version())
			require.NoError(t, err)
			for i, u := range ranges {
				t.Logf("   range %2d [%x-%x)", i, u.Start, u.End)
			}
			t.Logf("%+v", ranges)
			require.Contains(t, ranges, hot.AsRange())
			expected := []util.Range{hot.AsRange()}
			expected = append(expected, cold.AsRange())
			sortRanges(expected)
			require.Equal(t, expected, ranges)
		})
	}
}

type extractor interface {
	extract(t testing.TB) (elf, debugElf *pfelf.File)
	id() string
	version() uint16
}
type dockerPythonExtractor struct {
	name       string
	dockerfile string
	withDebug  bool
	ver        uint16
}

func (e dockerPythonExtractor) id() string {
	return e.name
}
func (e dockerPythonExtractor) version() uint16 {
	return e.ver
}
func (e dockerPythonExtractor) extract(t testing.TB) (elf, debugElf *pfelf.File) {
	d, _ := os.MkdirTemp("", "")
	t.Logf("%s %s", e.name, d)
	//d := t.TempDir()
	err := os.WriteFile(filepath.Join(d, "Dockerfile"), []byte(e.dockerfile), 0666)
	require.NoError(t, err)
	c := exec.Command("docker", "build",
		"--output=.",
		".")
	buffer := bytes.NewBuffer(nil)
	c.Stderr = buffer
	c.Dir = d
	err = c.Run()
	require.NoError(t, err, buffer.String())

	es, err := os.ReadDir(d)
	require.NoError(t, err)
	if e.withDebug {
		require.Len(t, es, 3)
	} else {
		require.Len(t, es, 2)
	}
	elfPath, debugElfPath := "", ""
	for _, entry := range es {
		n := entry.Name()
		if n == "Dockerfile" {
			continue
		}
		if strings.Contains(n, ".debug") {
			debugElfPath = n
		} else {
			elfPath = n
		}
	}
	t.Logf("%s %s", elfPath, debugElfPath)

	elfPath = filepath.Join(d, elfPath)

	inspectPath := filepath.Join(os.Getenv("HOME"), "Desktop", "__inspect__"+e.id())
	_ = os.Symlink(elfPath, inspectPath)

	elf, err = pfelf.Open(elfPath)
	require.NoError(t, err)
	t.Cleanup(func() {
		elf.Close()
	})
	if e.withDebug {
		debugElf, err = pfelf.Open(filepath.Join(d, debugElfPath))
		require.NoError(t, err)
		t.Cleanup(func() {
			debugElf.Close()
		})
	} else {
		s, _ := elf.ReadSymbols()
		if s != nil {
			_, err = s.LookupSymbolAddress("_PyEval_EvalFrameDefault.cold")
			if err == nil {
				debugElf = elf
			}
		}
	}

	return
}

func alpine(base string, ver uint16) dockerPythonExtractor {
	dockerfile := fmt.Sprintf(`
FROM %s as builder
RUN apk add python3 python3-dbg
RUN mkdir /out
RUN cp /usr/lib/debug/usr/lib/libpython*1.0.debug /out
RUN cp /usr/lib/libpython*1.0 /out
FROM scratch
COPY --from=builder /out /
`, base)
	return dockerPythonExtractor{
		ver:        ver,
		name:       "docker-alpine-" + base,
		dockerfile: dockerfile,
		withDebug:  true,
	}
}

func python(base string, name string, version uint16) dockerPythonExtractor {
	dockerfile := fmt.Sprintf(`
FROM %s as builder
RUN mkdir /out
RUN cp /usr/local/lib/libpython*1.0 /out
FROM scratch
COPY --from=builder /out /
`, base)
	return dockerPythonExtractor{

		ver:        version,
		name:       "docker-python-alpine-" + name + "-" + base,
		dockerfile: dockerfile,

		withDebug: false,
	}
}

func debian(base string, ver uint16) dockerPythonExtractor {
	dockerfile := fmt.Sprintf(`
FROM %s as builder
RUN apt-get update && apt-get -y install  python3 python3-dbg binutils original-awk grep
RUN <<EOF
set -ex
mkdir /out
cp /usr/bin/$(readlink /usr/bin/python3) /out
build_id=$(readelf -n /usr/bin/$(readlink /usr/bin/python3) | grep "Build ID" | awk '{print $3}')
dir_name=$(echo "$build_id" | cut -c1-2)
file_name=$(echo "$build_id" | cut -c3-).debug
debug_file_path="/usr/lib/debug/.build-id/$dir_name/$file_name"
cp $debug_file_path /out/$(readlink /usr/bin/python3).debug
EOF
FROM scratch
COPY --from=builder /out /
`, base)
	return dockerPythonExtractor{
		ver:        ver,
		name:       "docker-debian-" + base,
		dockerfile: dockerfile,
		withDebug:  true,
	}
}

type storeExtractor struct {
	ver     uint16
	storeId string
}

func (e storeExtractor) id() string {
	return e.storeId
}
func (e storeExtractor) version() uint16 {
	return e.ver
}

func (e storeExtractor) extract(t testing.TB) (elf, debugElf *pfelf.File) {
	s, err := modulestore.InitModuleStore(moduleStoreCachePath)
	require.NoError(t, err)
	parsedID, err := modulestore.IDFromString(e.id())
	require.NoError(t, err)
	buf := bytes.NewBuffer(nil)
	err = s.UnpackModule(parsedID, buf)
	require.NoError(t, err)
	_ = s.UnpackModuleToPath(parsedID, filepath.Join(os.Getenv("HOME"), "Desktop", "__inspect__"+e.id())) // todo remove
	file, err := pfelf.NewFile(bytes.NewReader(buf.Bytes()), 0, false)
	require.NoError(t, err)
	t.Cleanup(func() {
		file.Close()
	})
	return file, nil
}
