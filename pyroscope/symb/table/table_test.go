package table

import (
	"fmt"
	"io"
	"math"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testRange struct {
	va       uint64
	len      uint64
	depth    uint64
	funcName string
	fileName string
	line     uint32
}

func testDataRanges() []testRange {
	return []testRange{
		{va: 0x1000, len: 0x200, depth: 0, line: 2, funcName: "outer", fileName: "file1"},
		{va: 0x1050, len: 0x100, depth: 1, line: 4, funcName: "middle", fileName: "file2"},
		{va: 0x1075, len: 0x50, depth: 2, line: 7, funcName: "inner", fileName: "file3"},
		{va: 0x2000, len: 0x100, depth: 0, line: 13, funcName: "func1", fileName: "file4"},
		{va: 0x3000, len: 0x200, depth: 0, line: 32, funcName: "func2", fileName: "file5"},
	}
}

var testDataRanges1 = testDataRanges()
var testDataRanges2 = append(testDataRanges(), testRange{
	va: uint64(^uint32(0)) + 1, len: 0x200, depth: 0, line: 32, funcName: "largefunc1", fileName: "largefile1",
})
var testDataRanges3 = append(testDataRanges(), testRange{
	va: 0x5000, len: uint64(^uint32(0)) + 1, depth: 0, line: 32, funcName: "largefunc2", fileName: "largefile2",
})

func createTestFile(t testing.TB, ranges []testRange, option ...Option) string {
	path := t.TempDir() + "/test.symb"
	file, err := os.Create(path)
	require.NoError(t, err)
	defer file.Close()

	sb := newStringBuilder()
	rb := newRangesBuilder()

	for _, r := range ranges {
		funcOffset := sb.add(r.funcName)
		fileOffset := sb.add("")
		rb.add(r.va, r.len, r.depth, funcOffset, fileOffset)
	}
	o := options{}
	for _, opt := range option {
		opt(&o)
	}
	err = write(file, rb, sb, o)
	require.NoError(t, err)

	return path
}

func TestSymbTable(t *testing.T) {

	type lookupChecks struct {
		addr     uint64
		expected []LookupResult
	}

	type test struct {
		name       string
		testRanges []testRange
		checks     []lookupChecks
	}

	tests := []test{
		{"normal u32", testDataRanges1, []lookupChecks{
			{0x0999, nil}, // Before first function
			{0x1000, []LookupResult{{"outer", "", 0}}},                                      // Start of outer function
			{0x1025, []LookupResult{{"outer", "", 0}}},                                      // In outer function before middle
			{0x1050, []LookupResult{{"middle", "", 0}, {"outer", "", 0}}},                   // Start of middle function (inlined)
			{0x1074, []LookupResult{{"middle", "", 0}, {"outer", "", 0}}},                   // In middle function before inner
			{0x1075, []LookupResult{{"inner", "", 0}, {"middle", "", 0}, {"outer", "", 0}}}, // Start of inner function (inlined)
			{0x1080, []LookupResult{{"inner", "", 0}, {"middle", "", 0}, {"outer", "", 0}}}, // Inside inner function
			{0x10c4, []LookupResult{{"inner", "", 0}, {"middle", "", 0}, {"outer", "", 0}}}, // End of inner function
			{0x10c5, []LookupResult{{"middle", "", 0}, {"outer", "", 0}}},                   // Back to middle function
			{0x1149, []LookupResult{{"middle", "", 0}, {"outer", "", 0}}},                   // End of middle function
			{0x1150, []LookupResult{{"outer", "", 0}}},                                      // Back to outer function
			{0x1199, []LookupResult{{"outer", "", 0}}},                                      // End of outer function
			{0x1200, nil}, // Between functions
			{0x2000, []LookupResult{{"func1", "", 0}}}, // Start of func1
			{0x2050, []LookupResult{{"func1", "", 0}}}, // Middle of func1
			{0x3100, []LookupResult{{"func2", "", 0}}}, // Middle of func2
			{0x3200, nil}, // After last function
			{0x4000, nil}, // Way after last function
		}},
		{"u64 va", testDataRanges2, []lookupChecks{
			{0x0999, nil}, // Before first function
			{0x1000, []LookupResult{{"outer", "", 0}}},                                      // Start of outer function
			{0x1025, []LookupResult{{"outer", "", 0}}},                                      // In outer function before middle
			{0x1050, []LookupResult{{"middle", "", 0}, {"outer", "", 0}}},                   // Start of middle function (inlined)
			{0x1074, []LookupResult{{"middle", "", 0}, {"outer", "", 0}}},                   // In middle function before inner
			{0x1075, []LookupResult{{"inner", "", 0}, {"middle", "", 0}, {"outer", "", 0}}}, // Start of inner function (inlined)
			{0x1080, []LookupResult{{"inner", "", 0}, {"middle", "", 0}, {"outer", "", 0}}}, // Inside inner function
			{0x10c4, []LookupResult{{"inner", "", 0}, {"middle", "", 0}, {"outer", "", 0}}}, // End of inner function
			{0x10c5, []LookupResult{{"middle", "", 0}, {"outer", "", 0}}},                   // Back to middle function
			{0x1149, []LookupResult{{"middle", "", 0}, {"outer", "", 0}}},                   // End of middle function
			{0x1150, []LookupResult{{"outer", "", 0}}},                                      // Back to outer function
			{0x1199, []LookupResult{{"outer", "", 0}}},                                      // End of outer function
			{0x1200, nil}, // Between functions
			{0x2000, []LookupResult{{"func1", "", 0}}}, // Start of func1
			{0x2050, []LookupResult{{"func1", "", 0}}}, // Middle of func1
			{0x3100, []LookupResult{{"func2", "", 0}}}, // Middle of func2
			{0x3200, nil}, // After last function
			{0x4000, nil}, // Way after last function
		}},
		{"u64 fields", testDataRanges3, []lookupChecks{
			{0x0999, nil}, // Before first function
			{0x1000, []LookupResult{{"outer", "", 0}}},                                      // Start of outer function
			{0x1025, []LookupResult{{"outer", "", 0}}},                                      // In outer function before middle
			{0x1050, []LookupResult{{"middle", "", 0}, {"outer", "", 0}}},                   // Start of middle function (inlined)
			{0x1074, []LookupResult{{"middle", "", 0}, {"outer", "", 0}}},                   // In middle function before inner
			{0x1075, []LookupResult{{"inner", "", 0}, {"middle", "", 0}, {"outer", "", 0}}}, // Start of inner function (inlined)
			{0x1080, []LookupResult{{"inner", "", 0}, {"middle", "", 0}, {"outer", "", 0}}}, // Inside inner function
			{0x10c4, []LookupResult{{"inner", "", 0}, {"middle", "", 0}, {"outer", "", 0}}}, // End of inner function
			{0x10c5, []LookupResult{{"middle", "", 0}, {"outer", "", 0}}},                   // Back to middle function
			{0x1149, []LookupResult{{"middle", "", 0}, {"outer", "", 0}}},                   // End of middle function
			{0x1150, []LookupResult{{"outer", "", 0}}},                                      // Back to outer function
			{0x1199, []LookupResult{{"outer", "", 0}}},                                      // End of outer function
			{0x1200, nil}, // Between functions
			{0x2000, []LookupResult{{"func1", "", 0}}}, // Start of func1
			{0x2050, []LookupResult{{"func1", "", 0}}}, // Middle of func1
			{0x3100, []LookupResult{{"func2", "", 0}}}, // Middle of func2
			{0x3200, nil}, // After last function
			{0x4000, nil}, // Way after last function
		}},
	}

	for _, tc := range tests {

		t.Run(tc.name, func(t *testing.T) {
			path := createTestFile(t, tc.testRanges, WithFiles(), WithCRC())
			symtab, err := OpenPath(path, WithFiles(), WithCRC())
			require.NoError(t, err)
			t.Cleanup(func() {
				symtab.Close()
			})

			for _, check := range tc.checks {
				check := check
				t.Run(fmt.Sprintf("fn_%x", check.addr), func(t *testing.T) {
					got, _ := symtab.Lookup(check.addr)
					assert.Equal(t, check.expected, got)
				})
			}

		})

	}
}

func TestSymbTabErrors(t *testing.T) {
	_, err := OpenPath("nonexistent")
	require.Error(t, err)

	_, err = OpenPath("")
	require.Error(t, err)
}

func TestSymbTabClose(t *testing.T) {
	path := createTestFile(t, testDataRanges1)

	symtab, err := OpenPath(path)
	require.NoError(t, err)

	symtab.Close()
	symtab.Close()
}

func BenchmarkFindFunc(b *testing.B) {
	path := createTestFile(b, testDataRanges1)

	symtab, err := OpenPath(path)
	require.NoError(b, err)
	defer symtab.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err = symtab.Lookup(0x1075) // Test with an inlined function case
		require.NoError(b, err)
	}
}

func TestLibc(t *testing.T) {
	var err error
	libc, err := os.Open("../testdata/64b17fbac799e68da7ebd9985ddf9b5cb375e6.debug")
	require.NoError(t, err)
	defer libc.Close()

	tableFile, err := os.Create(t.TempDir() + "/out")
	require.NoError(t, err)
	defer tableFile.Close()
	err = FDToTable(libc, tableFile, WithCRC(), WithFiles())
	require.NoError(t, err)

	_, err = tableFile.Seek(0, io.SeekStart)
	require.NoError(t, err)
	table, err := OpenFile(tableFile, WithCRC(), WithFiles())
	require.NoError(t, err)

	check := func(addr uint64, expected []LookupResult) {
		syms, err := table.Lookup(addr)
		require.NoError(t, err)
		fmt.Printf("%v\n", syms)
		assert.NotEmpty(t, syms)
		assert.Equal(t, expected, syms)
	}
	check(0x11ba61, []LookupResult{{"__GI___libc_read", "../sysdeps/unix/sysv/linux/read.c", 0}})
	check(0x18833e, []LookupResult{{"__memcmp_avx2_movbe", "../sysdeps/x86_64/multiarch/memcmp-avx2-movbe.S", 0}})
	check(0x9ca94, []LookupResult{{"start_thread", "./nptl/pthread_create.c", 0}})
	check(0x129c3c, []LookupResult{{"__clone3", "../sysdeps/unix/sysv/linux/x86_64/clone3.S", 0}})
	check(0x98d61, []LookupResult{{"__futex_abstimed_wait_common64", "./nptl/futex-internal.c", 0},
		{"__futex_abstimed_wait_common", "./nptl/futex-internal.c", 0},
		{"__GI___futex_abstimed_wait_cancelable64", "./nptl/futex-internal.c", 0}})
	check(0x9bc7e, []LookupResult{{"__pthread_cond_wait_common", "./nptl/pthread_cond_wait.c", 0},
		{"___pthread_cond_timedwait64", "./nptl/pthread_cond_wait.c", 0}})
}

func BenchmarkLibc(b *testing.B) {
	var err error

	libc, err := os.Open("../testdata/libc.debug")
	require.NoError(b, err)
	defer libc.Close()

	tableFile, err := os.Create(b.TempDir() + "/out")
	require.NoError(b, err)
	defer tableFile.Close()
	err = FDToTable(libc, tableFile)
	require.NoError(b, err)

	_, err = tableFile.Seek(0, io.SeekStart)
	require.NoError(b, err)
	table, err := OpenFile(tableFile)
	require.NoError(b, err)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = table.Lookup(0x11ba61)
		_, _ = table.Lookup(0x18833e)
		_, _ = table.Lookup(0x9ca94)
		_, _ = table.Lookup(0x129c3c)
		_, _ = table.Lookup(0x98d61)
		_, _ = table.Lookup(0x9bc7e)
	}
}

func TestSelfAddrLookup(t *testing.T) {
	tests := []struct {
		addr uint64
		name string
	}{
		{
			addr: uint64(reflect.ValueOf(TestSelfAddrLookup).Pointer()),
			name: "go.opentelemetry.io/ebpf-profiler/pyroscope/symb/table.TestSelfAddrLookup",
		},
	}

	exef, err := os.Open("/proc/self/exe")
	require.NoError(t, err)

	dst := t.TempDir() + "/out"
	dstf, err := os.Create(dst)
	require.NoError(t, err)

	err = FDToTable(exef, dstf)
	require.NoError(t, err)
	require.NoError(t, err)

	table, err := OpenPath(dst)
	require.NoError(t, err)
	require.NotNil(t, table)
	defer table.Close()

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.NotEqual(t, uint32(0), test.addr)
			res, _ := table.Lookup(test.addr)
			res[0].File = "" // Don't check file
			expected := []LookupResult{{test.name, "", 0}}
			assert.Equal(t, expected, res)
		})
	}
}

func TestLibcAddrLookup(t *testing.T) {
	dst := "../testdata/libc.gtbl"
	//generateLibcTable(t, dst)
	table, err := OpenPath(dst)
	require.NoError(t, err)
	require.NotNil(t, table)

	readelfData, err := os.ReadFile("../testdata/libc_readelf_funcs.txt")
	require.NoError(t, err)
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
		require.NoError(t, err)
		if _, ok := checkedAddresses[iaddr]; ok {
			continue
		}
		checkedAddresses[iaddr] = struct{}{}
		assert.LessOrEqual(t, iaddr, uint64(math.MaxUint32))

		res, _ := table.Lookup(iaddr)
		require.NotEmpty(t, res)
		require.Len(t, res, 1)
		//assert.Contains(t, res[0].Name, name) // todo
		//fmt.Printf("%20s  %20s\n", name, res[0].Name)
		checked++
	}

	assert.Greater(t, checked, 100)
}

func generateLibcTable(t *testing.T, dst string) {
	dstf, err := os.Create(dst)
	require.NoError(t, err)
	defer dstf.Close()
	srcf, err := os.Open("../testdata/libc.debug")
	require.NoError(t, err)
	defer srcf.Close()
	err = FDToTable(srcf, dstf)
	require.NoError(t, err)
	require.Fail(t, "generated libc.gtbl")
}
