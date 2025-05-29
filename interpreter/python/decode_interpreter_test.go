package python

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/tools/coredump/modulestore"
	"go.opentelemetry.io/ebpf-profiler/util"
)

const moduleStoreCachePath = "../../tools/coredump/modulecache"

func TestDecodeInterpreter(t *testing.T) {
	testdata := []struct {
		id       string
		expected []util.Range
	}{
		{
			id: "497dd0d2b4a80bfd11339306c84aa752d811f612a398cb526a0a9ac2f426c0b8",
			expected: []util.Range{
				{Start: 559770, End: 616313},
				{Start: 1513344, End: 1513706},
			},
		},
		{
			id: "11ce00a6490d5e4ef941e1f51faaddf40c088a1376f028cbc001985b779397ce",
			expected: []util.Range{
				{Start: 0x325C10, End: 0x331E54},
			},
		},
		{
			id: "1a2eb220c22ae7ba8aaf8b243e57dbc25542f8c9c269ed6100c7ad5aea7c3ada",
			expected: []util.Range{
				{Start: 0x325C10, End: 0x331E54},
			},
		},
	}
	for _, td := range testdata {
		t.Run(td.id, func(t *testing.T) {
			python, err := openStoreElf(td.id)
			require.NoError(t, err)
			defer python.Close()
			sym, err := python.LookupSymbol("_PyEval_EvalFrameDefault")
			require.NoError(t, err)
			t.Logf("starting at %x", sym.Address)
			actual, err := decodeInterpreterRanges(python, uint64(sym.Address))
			require.NoError(t, err)
			require.Equal(t, td.expected, actual)
		})
	}
}

//todo docker test

func BenchmarkDecodeInterpreter(b *testing.B) {
	libPython, err := openStoreElf("497dd0d2b4a80bfd11339306c84aa752d811f612a398cb526a0a9ac2f426c0b8")
	if err != nil {
		b.FailNow()
	}
	sym, err := libPython.LookupSymbol("_PyEval_EvalFrameDefault")
	if err != nil {
		b.FailNow()
	}
	defer libPython.Close()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ranges, err := decodeInterpreterRanges(libPython, uint64(sym.Address))
		if err != nil || len(ranges) != 2 {
			b.FailNow()
		}
	}
}

func openStoreElf(id string) (*pfelf.File, error) {
	s, err := modulestore.InitModuleStore(moduleStoreCachePath)
	if err != nil {
		return nil, err
	}
	parsedID, err := modulestore.IDFromString(id)
	if err != nil {
		return nil, err
	}
	buf := bytes.NewBuffer(nil)
	err = s.UnpackModule(parsedID, buf)
	if err != nil {
		return nil, err
	}
	s.UnpackModuleToPath(parsedID, "/home/korniltsev/Desktop/"+id)
	file, err := pfelf.NewFile(bytes.NewReader(buf.Bytes()), 0, false)
	if err != nil {
		return nil, err
	}
	return file, nil
}
