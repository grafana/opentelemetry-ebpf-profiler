package table

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io"
	"math"
	"os"
	"strconv"
	"strings"
	"testing"
)

func createTestFile(t testing.TB) string {
	path := t.TempDir() + "/test.symb"
	file, err := os.Create(path)
	require.NoError(t, err)
	defer file.Close()

	hdr := header{
		magic:         magic,
		version:       version,
		rangesOffset:  0,
		stringsOffset: 0,
	}
	err = binary.Write(file, binary.LittleEndian, hdr)
	require.NoError(t, err)

	currentPos, err := file.Seek(0, 1)
	require.NoError(t, err)
	padding := (16 - (currentPos % 16)) % 16
	_, err = file.Write(make([]byte, padding))
	require.NoError(t, err)

	rangesOffset, err := file.Seek(0, 1)
	require.NoError(t, err)

	ranges := []entry{
		{va: 0x1000, length: 0x200, depth: 0, fun: 0},  // points to "outer"
		{va: 0x1050, length: 0x100, depth: 1, fun: 9},  // points to "middle"
		{va: 0x1075, length: 0x50, depth: 2, fun: 19},  // points to "inner"
		{va: 0x2000, length: 0x100, depth: 0, fun: 28}, // points to "func1"
		{va: 0x3000, length: 0x200, depth: 0, fun: 37}, // points to "func2"
	}

	for _, e := range ranges {
		err = binary.Write(file, binary.LittleEndian, e)
		require.NoError(t, err)
	}

	currentPos, err = file.Seek(0, 1)
	require.NoError(t, err)
	padding = (16 - (currentPos % 16)) % 16
	_, err = file.Write(make([]byte, padding))
	require.NoError(t, err)

	stringsOffset, err := file.Seek(0, 1)
	require.NoError(t, err)

	// Write strings
	strings := []string{"outer", "middle", "inner", "func1", "func2"}
	for _, s := range strings {
		length := uint32(len(s))
		err = binary.Write(file, binary.LittleEndian, length)
		require.NoError(t, err)
		_, err = file.Write([]byte(s))
		require.NoError(t, err)
	}

	_, err = file.Seek(0, 0)
	require.NoError(t, err)
	hdr.rangesOffset = uint64(rangesOffset)
	hdr.stringsOffset = uint64(stringsOffset)
	err = binary.Write(file, binary.LittleEndian, hdr)
	require.NoError(t, err)

	return path
}

func TestSymbTab(t *testing.T) {
	path := createTestFile(t)

	symtab, err := OpenPath(path)
	require.NoError(t, err)
	defer symtab.Close()

	tests := []struct {
		addr     uint64
		expected []string
	}{
		{0x0999, nil},                                  // Before first function
		{0x1000, []string{"outer"}},                    // Start of outer function
		{0x1025, []string{"outer"}},                    // In outer function before middle
		{0x1050, []string{"middle", "outer"}},          // Start of middle function (inlined)
		{0x1074, []string{"middle", "outer"}},          // In middle function before inner
		{0x1075, []string{"inner", "middle", "outer"}}, // Start of inner function (inlined)
		{0x1080, []string{"inner", "middle", "outer"}}, // Inside inner function
		{0x10c4, []string{"inner", "middle", "outer"}}, // End of inner function
		{0x10c5, []string{"middle", "outer"}},          // Back to middle function
		{0x1149, []string{"middle", "outer"}},          // End of middle function
		{0x1150, []string{"outer"}},                    // Back to outer function
		{0x1199, []string{"outer"}},                    // End of outer function
		{0x1200, nil},                                  // Between functions
		{0x2000, []string{"func1"}},                    // Start of func1
		{0x2050, []string{"func1"}},                    // Middle of func1
		{0x3100, []string{"func2"}},                    // Middle of func2
		{0x3200, nil},                                  // After last function
		{0x4000, nil},                                  // Way after last function
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("fn_%x", tc.addr), func(t *testing.T) {
			got := symtab.Lookup(tc.addr, nil)
			assert.Equal(t, tc.expected, got)
		})
	}
}

func TestSymbTabErrors(t *testing.T) {
	_, err := OpenPath("nonexistent")
	assert.Error(t, err)

	_, err = OpenPath("")
	assert.Error(t, err)
}

func TestSymbTabClose(t *testing.T) {
	path := createTestFile(t)

	symtab, err := OpenPath(path)
	require.NoError(t, err)

	symtab.Close()
	symtab.Close()
}

func BenchmarkFindFunc(b *testing.B) {
	path := createTestFile(b)

	symtab, err := OpenPath(path)
	require.NoError(b, err)
	defer symtab.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		symtab.Lookup(0x1075, nil) // Test with an inlined function case
	}
}

func TestLibc(t *testing.T) {
	var err error
	//libc, err := os.Open("/usr/lib/x86_64-linux-gnu/libc.so.6")
	//require.NoError(t, err)
	//defer libc.Close()
	libc, err := os.Open("/usr/lib/debug/.build-id/6d/64b17fbac799e68da7ebd9985ddf9b5cb375e6.debug")
	require.NoError(t, err)
	defer libc.Close()

	tableFile, err := os.Create(t.TempDir() + "/out")
	require.NoError(t, err)
	defer tableFile.Close()
	err = FDToTable(libc, nil, tableFile)
	require.NoError(t, err)

	//tableFile, err := os.Open("/tmp/symb-cache/e8735d5b23f3627ce8735d5b23f3627c")
	//require.NoError(t, err)

	tableFile.Seek(io.SeekStart, 0)
	table, err := OpenFile(tableFile)
	require.NoError(t, err)

	check := func(syms []string, expected []string) {
		fmt.Printf("%v\n", syms)
		assert.NotEmpty(t, syms)
		assert.Equal(t, expected, syms)
	}
	check(table.Lookup(0x11ba61, nil), []string{"__GI___libc_read"})
	check(table.Lookup(0x18833e, nil), []string{"__memcmp_avx2_movbe"})
	check(table.Lookup(0x9ca94, nil), []string{"start_thread"})
	check(table.Lookup(0x129c3c, nil), []string{"__clone3"})
	check(table.Lookup(0x98d61, nil), []string{"__futex_abstimed_wait_common64", "__futex_abstimed_wait_common", "__GI___futex_abstimed_wait_cancelable64"})
	check(table.Lookup(0x9bc7e, nil), []string{"__pthread_cond_wait_common", "___pthread_cond_timedwait64"})
}

func BenchmarkLibc(b *testing.B) {
	var err error

	libc, err := os.Open("../testdata/libc.debug")
	require.NoError(b, err)
	defer libc.Close()

	tableFile, err := os.Create(b.TempDir() + "/out")
	require.NoError(b, err)
	defer tableFile.Close()
	err = FDToTable(libc, nil, tableFile)
	require.NoError(b, err)

	tableFile.Seek(io.SeekStart, 0)
	table, err := OpenFile(tableFile)
	require.NoError(b, err)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = table.Lookup(0x11ba61, nil)
		_ = table.Lookup(0x18833e, nil)
		_ = table.Lookup(0x9ca94, nil)
		_ = table.Lookup(0x129c3c, nil)
		_ = table.Lookup(0x98d61, nil)
		_ = table.Lookup(0x9bc7e, nil)
	}
}

func TestClickHouse(t *testing.T) {
	t.Skip()
	path := "/home/korniltsev/p/clickhouse"
	exef, _ := os.Open(path)
	dst := t.TempDir() + "/out"
	dstf, _ := os.Create(dst)
	err := FDToTable(exef, nil, dstf)
	assert.NoError(t, err)

	table, err := OpenPath(dst)
	require.NoError(t, err)
	fmt.Printf("table: %s\n", table.String())

}

func TestSelfAddrLookup(t *testing.T) {

	tests := []struct {
		addr uint64
		name string
	}{
		{
			addr: uint64(findTestSelfAddressRelativeToElfBase()),
			name: "go.opentelemetry.io/ebpf-profiler/reporter/pyroscope/symb/table.TestSelfAddrLookup",
		},
	}

	exef, err := os.Open("/proc/self/exe")
	require.NoError(t, err)

	dst := t.TempDir() + "/out"
	dstf, err := os.Create(dst)
	require.NoError(t, err)

	err = FDToTable(exef, nil, dstf)
	assert.NoError(t, err)
	assert.NoError(t, err)

	table, err := OpenPath(dst)
	require.NoError(t, err)
	require.NotNil(t, table)
	defer table.Close()

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.NotEqual(t, uint32(0), test.addr)
			res := table.Lookup(test.addr, nil)
			require.Len(t, res, 1)
			assert.Equal(t, test.name, res[0])
		})
	}
}

func TestLibcAddrLookup(t *testing.T) {
	dst := "../testdata/libc.gtbl"

	//err := ExeToTable("/lib/x86_64-linux-gnu/libc.so.6", dst)
	//assert.NoError(t, err)

	table, err := OpenPath(dst)
	require.NoError(t, err)
	require.NotNil(t, table)

	readelfData, err := os.ReadFile("../testdata/libc_readelf_funcs.txt")
	assert.NoError(t, err)
	expectedFuncLines := strings.Split(string(readelfData), "\n")

	checked := 0
	checkedAddresses := map[uint64]struct{}{}
	for _, line := range expectedFuncLines {
		fields := strings.Fields(line)
		if len(fields) != 8 {
			continue
		}
		addr := fields[1]
		name := fields[7]
		if strings.Contains(name, "@") {
			name = strings.Split(name, "@")[0]
		}
		iaddr, err := strconv.ParseUint(addr, 16, 64)
		assert.NoError(t, err)
		if _, ok := checkedAddresses[iaddr]; ok {
			continue
		}
		checkedAddresses[iaddr] = struct{}{}
		assert.True(t, iaddr >= 0 && iaddr <= math.MaxUint32)

		res := table.Lookup(uint64(iaddr), nil)
		require.NotEmpty(t, res)
		require.Len(t, res, 1)
		assert.Contains(t, name, res[0])
		checked++
	}

	assert.Greater(t, checked, 100)
}

func findTestSelfAddressRelativeToElfBase() uint64 {
	f, err := elf.Open("/proc/self/exe")
	if err != nil {
		return 0
	}
	defer f.Close()

	syms, err := f.Symbols()
	if err != nil {
		return 0
	}

	for _, sym := range syms {
		if strings.Contains(sym.Name, "TestSelfAddrLookup") {
			return sym.Value
		}
	}
	return 0
}
