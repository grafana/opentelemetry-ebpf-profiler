package python

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/asm/amd"
	"go.opentelemetry.io/ebpf-profiler/asm/dfs"
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
			elf: storeExtractor{"497dd0d2b4a80bfd11339306c84aa752d811f612a398cb526a0a9ac2f426c0b8"},
			expected: []util.Range{
				{Start: 559770, End: 616313},
				{Start: 1513344, End: 1513706},
			},
		},
		{
			elf: storeExtractor{"11ce00a6490d5e4ef941e1f51faaddf40c088a1376f028cbc001985b779397ce"},
			expected: []util.Range{
				{Start: 0x325C10, End: 0x331E54},
			},
		},
		{
			elf: storeExtractor{"1a2eb220c22ae7ba8aaf8b243e57dbc25542f8c9c269ed6100c7ad5aea7c3ada"},
			expected: []util.Range{
				{Start: 0x10BABF, End: 0x10BAD9}, // unreachable ud2 TODO exclude?
				{Start: 0x10C0E0, End: 0x11867a},
			},
		},
		{
			elf: storeExtractor{"abc9170dfb10b8a926d2376de94aa9a0ffd7b0ea4febf80606b4bba6c5ffa386"},
			expected: []util.Range{
				{Start: 0x7a796, End: 0x7df87},
				{Start: 0x1726e0, End: 0x17b3de},
			},
		},
		{
			elf: storeExtractor{"67997ac257675599247dc0445f4d2705f67e203678fb9920162bc2cd7f9d0009"},
			expected: []util.Range{
				{Start: 0x1f47a0, End: 0x2013ff},
			},
		},
		{
			elf: storeExtractor{"b14a0e943b0480bd6d590fa0b2b2734763b3e134625e84ab1c363bb2f77e0a2a"},
			expected: []util.Range{
				{Start: 0xFA0AC, End: 0xFA0AC + 0x000024F7},
				{Start: 0x1bed10, End: 0x1c922b},
			},
		},
		{
			elf: debianExtractor("debian@sha256:1bcac6cbf17ce95f085a578bcab3d5bee7725fb23d808c190d86d541c757c9f6"),
			expected: []util.Range{
				{Start: 0x430f05, End: 0x430f05 + 0x3659},
				{Start: 0x52b0f0, End: 0x538a4c},
			},
		},
		{
			elf:      debianExtractor("debian@sha256:4f71d532a25f8f0690ac6bf37616a3b2fc051d5535f3e32489fe8a62093b931d"),
			expected: []util.Range{},
		},
		{
			elf:      localFile{"/tmp/2891076654/python3.9"},
			expected: []util.Range{},
		},
	}
	for _, td := range testdata {
		t.Run(td.elf.id(), func(t *testing.T) {
			t.Parallel()
			//python, err := openStoreElf(td.id)
			python, _ := td.elf.extract(t)
			sym, err := python.LookupSymbol("_PyEval_EvalFrameDefault")
			require.NoError(t, err)
			t.Logf("starting at %x-%x", sym.Address, uint64(sym.Address)+sym.Size)
			start := util.Range{Start: uint64(sym.Address), End: uint64(sym.Address) + sym.Size}
			actual, err := decodeInterpreterRanges(python, start)
			require.NoError(t, err)
			require.Equal(t, td.expected, actual)
		})
	}
}

//todo docker test

func BenchmarkDecodeInterpreter(b *testing.B) {
	libPython, _ := storeExtractor{"497dd0d2b4a80bfd11339306c84aa752d811f612a398cb526a0a9ac2f426c0b8"}.extract(b)
	sym, err := libPython.LookupSymbol("_PyEval_EvalFrameDefault")
	if err != nil {
		b.FailNow()
	}
	defer libPython.Close()
	b.ResetTimer()
	start := util.Range{Start: uint64(sym.Address), End: uint64(sym.Address) + sym.Size}
	for i := 0; i < b.N; i++ {
		ranges, err := decodeInterpreterRanges(libPython, start)
		if err != nil || len(ranges) != 2 {
			b.FailNow()
		}
	}
}

func TestRecoverJumpTables(t *testing.T) {
	type blockCheck struct {
		src           uint64
		jumpsChecksum uint32
	}
	testcases := []struct {
		elf extractor
		//opcodeTable uint64
		blocks []blockCheck
	}{
		{
			elf: storeExtractor{"abc9170dfb10b8a926d2376de94aa9a0ffd7b0ea4febf80606b4bba6c5ffa386"},
			//opcodeTable: 0x55c160,
			blocks: []blockCheck{
				{0x172866, 0x0},
				{0x1766e0, 0xaba1677},
				{0x176dff, 0xaba1677},
				{0x17a3fb, 0xaba1677},
			},
		},
		{
			elf: storeExtractor{"11ce00a6490d5e4ef941e1f51faaddf40c088a1376f028cbc001985b779397ce"},
			//opcodeTable: 0x13C7270,
			blocks: []blockCheck{
				{0x33110A, 0x4faa3f80},
			},
		},
		{
			elf: storeExtractor{"b14a0e943b0480bd6d590fa0b2b2734763b3e134625e84ab1c363bb2f77e0a2a"},
			//opcodeTable: 0x3BFC80,
			blocks: []blockCheck{
				{0x1bedc8, 0xb0290d15},
			},
		},
		{
			// 11.11-slim
			elf: debianExtractor("debian@sha256:4f71d532a25f8f0690ac6bf37616a3b2fc051d5535f3e32489fe8a62093b931d"),
			//opcodeTable: 0x6DF200,
			blocks: []blockCheck{
				{0x514084, 0x484ce97e},
				//{0x51aae5, 0x8814e773},
			},
			//indirect jump at bb 514084 => 256 jumps
			//indirect jump at bb 51aae5 => 0 jumps
		},
	}
	for _, td := range testcases {
		t.Run(td.elf.id(), func(t *testing.T) {
			e, _ := td.elf.extract(t)
			sym, err := e.LookupSymbol("_PyEval_EvalFrameDefault")
			require.NoError(t, err)
			d := new(dfs.DFS)
			d.AddBasicBlock(uint64(sym.Address))
			r := rangesRecoverer{
				ef:                      e,
				d:                       d,
				indirectJumpDestination: nil,
				recoveredTables:         make(map[uint64]struct{}),
			}
			for i := 0; i < 3; i++ {
				indirectJumpsFrom := map[uint64]struct{}{}
				err = amd.Explore(e, d, indirectJumpsFrom)
				require.NoError(t, err)

				recovered, err := r.recoverIndirectJumps(indirectJumpsFrom)
				require.NoError(t, err)
				if recovered == 0 {
					break
				}
			}
			//assert.Equal(t, td.opcodeTable, r.opcodeTableAddress)
			for _, b := range td.blocks {
				t.Run(fmt.Sprintf("%x", b.src), func(t *testing.T) {
					r.recoveredTables = make(map[uint64]struct{})
					bb := d.FindBasicBlock(b.src)
					require.NotNil(t, bb)
					err = r.collectIndirectJumpDestinations(bb)
					require.NoError(t, err)
					checksum := jumpsChecksum(r.indirectJumpDestination)
					assert.Equal(t, b.jumpsChecksum, checksum)
				})
			}
		})
	}
}

func jumpsChecksum(dat []uint64) uint32 {
	hash32 := crc32.New(crc32.MakeTable(crc32.Castagnoli))
	bs := [8]byte{}
	for _, v := range dat {
		binary.LittleEndian.PutUint64(bs[:], v)
		_, _ = hash32.Write(bs[:])
	}
	return hash32.Sum32()
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
	if runtime.GOARCH != "amd64" {
		t.Skip("only amd64 needed")
	}

	testdata := []dockerPythonExtractor{
		//alpineExtractor("alpine:latest"),
		//alpineTestcase("alpine:3.22.0"),
		//alpineTestcase("alpine:3.21.3"),
		//alpineTestcase("alpine:3.21.2"),
		//alpineTestcase("alpine:3.21.1"),
		//alpineTestcase("alpine:3.21.0"),
		//alpineTestcase("alpine:3.20.6"),
		//alpineTestcase("alpine:3.20.5"),
		//alpineTestcase("alpine:3.20.4"),
		//alpineTestcase("alpine:3.20.3"),
		//alpineTestcase("alpine:3.20.2"),
		//alpineTestcase("alpine:3.20.1"),
		//alpineTestcase("alpine:3.20.0"),
		//alpineTestcase("alpine:3.19.7"),
		//alpineTestcase("alpine:3.19.6"),
		//alpineTestcase("alpine:3.19.5"),
		//alpineTestcase("alpine:3.19.4"),
		//alpineTestcase("alpine:3.19.3"),
		//alpineTestcase("alpine:3.19.2"),
		//alpineTestcase("alpine:3.19.1"),
		//alpineTestcase("alpine:3.19.0"),
		debianExtractor("debian:testing"),
		debianExtractor("debian:testing-slim"),
		debianExtractor("debian:12.11"),
		debianExtractor("debian:12.11-slim"),
		debianExtractor("debian:11.11"),
		debianExtractor("debian:11.11-slim"),
	}
	for _, td := range testdata {
		t.Run(td.name, func(t *testing.T) {

			t.Parallel()
			elf, debugElf := td.extract(t)

			debugSymbols, err := debugElf.ReadSymbols()
			require.NoError(t, err)
			cold, err := debugSymbols.LookupSymbol("_PyEval_EvalFrameDefault.cold")
			require.NoError(t, err)
			t.Logf("cold %x : %x", cold.Address, cold.Size)

			hot, err := elf.LookupSymbol("_PyEval_EvalFrameDefault")
			require.NoError(t, err)

			ranges, err := decodeInterpreterRanges(elf, hot.AsRange())
			require.NoError(t, err)
			t.Logf("%+v", ranges)
			require.Contains(t, ranges, hot.AsRange())
			if cold.Size > 2 {
				require.Len(t, ranges, 2)
				require.Contains(t, ranges, cold.AsRange())
			} else {
				// likely a small range with just ud2 instruction which we don't
				// care about
			}
		})
	}
}

type extractor interface {
	extract(t testing.TB) (elf, debugElf *pfelf.File)
	id() string
}
type dockerPythonExtractor struct {
	name       string
	dockerfile string
}

func (e dockerPythonExtractor) id() string {
	return e.name
}
func (e dockerPythonExtractor) extract(t testing.TB) (elf, debugElf *pfelf.File) {
	d, _ := os.MkdirTemp("", "")
	t.Logf("%s %s", e.name, d)
	//d := t.TempDir()
	err := os.WriteFile(filepath.Join(d, "Dockerfile"), []byte(e.dockerfile), 0666)
	require.NoError(t, err)
	c := exec.Command("docker", "build",
		"-t", "test-"+e.name,
		"--output=.",
		"--pull",
		".")
	c.Dir = d
	err = c.Run()
	require.NoError(t, err)

	es, err := os.ReadDir(d)
	require.NoError(t, err)
	require.Len(t, es, 3)
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
	debugElf, err = pfelf.Open(filepath.Join(d, debugElfPath))
	require.NoError(t, err)
	t.Cleanup(func() {
		debugElf.Close()
	})

	return
}

func alpineExtractor(base string) dockerPythonExtractor {
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
		name:       "docker-alpine-" + base,
		dockerfile: dockerfile,
	}
}

func debianExtractor(base string) dockerPythonExtractor {
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
		name:       "docker-debian-" + base,
		dockerfile: dockerfile,
	}
}

type storeExtractor struct {
	storeId string
}

func (e storeExtractor) id() string {
	return e.storeId
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

type localFile struct {
	f string
}

func (e localFile) id() string {
	return strings.ReplaceAll(e.f, "/", "_")
}
func (e localFile) extract(t testing.TB) (elf, debugElf *pfelf.File) {
	storeElf, err := pfelf.Open(e.f)
	require.NoError(t, err)
	t.Cleanup(func() {
		storeElf.Close()
	})
	return storeElf, nil
}

func TestName(t *testing.T) {
	elf := debianExtractor("debian@sha256:4f71d532a25f8f0690ac6bf37616a3b2fc051d5535f3e32489fe8a62093b931d")
	e, _ := elf.extract(t)
	table := make([]byte, 166*8)
	_, err := e.ReadVirtualMemory(table, 0x6DEC40)
	require.NoError(t, err)

	hash32 := crc32.New(crc32.MakeTable(crc32.Castagnoli))
	hash32.Write(table)
	h := hash32.Sum32()
	t.Logf("%x", h)
}
