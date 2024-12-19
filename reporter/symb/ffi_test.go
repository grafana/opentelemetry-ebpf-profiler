package symb

import (
	"debug/elf"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"math"
	"os"
	"strconv"
	"strings"
	"testing"
)

type mycb struct {
	cnt int
}

func (m *mycb) VisitRange(elfVA uint64, length uint32, depth uint32, function string) {
	m.cnt++
}
func TestRaneExtractor(t *testing.T) {

	f, err := os.Open("/proc/self/exe")
	require.NoError(t, err)

	v := new(mycb)
	err = RangeExtractor(f, v)
	require.NoError(t, err)
	assert.Greater(t, v.cnt, 0)
}

func TestSelfAddrLookup(t *testing.T) {

	tests := []struct {
		addr uint64
		name string
	}{
		{
			addr: uint64(findTestSelfAddressRelativeToElfBase()),
			name: "go.opentelemetry.io/ebpf-profiler/reporter/symb.TestSelfAddrLookup",
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
	dst := "testdata/libc.gtbl"

	//err := ExeToTable("/lib/x86_64-linux-gnu/libc.so.6", dst)
	//assert.NoError(t, err)

	table, err := OpenPath(dst)
	require.NoError(t, err)
	require.NotNil(t, table)

	readelfData, err := os.ReadFile("testdata/libc_readelf_funcs.txt")
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

func TestClickHouse(t *testing.T) {
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
