package gsym

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGSYMWriter(t *testing.T) {
	w := NewWriter()
	w.AddFuncInfo(FunctionInfo{
		Addr: 0xef,
		Name: w.AddString("main.main"),
		Size: 0x10,
	})
	w.AddFuncInfo(FunctionInfo{
		Addr: 0x200,
		Name: w.AddString("main.foo"),
		Size: 0x20,
	})
	ii := &InlineInfo{
		Name:     w.AddString("inline1"),
		CallFile: 0,
		CallLine: 0,
		Ranges:   []AddressRange{{Start: 0xcafe000, End: 0xcafe100}},
		Children: []*InlineInfo{
			{
				Name:     w.AddString("inline2"),
				CallFile: 0,
				CallLine: 0,
				Ranges:   []AddressRange{{Start: 0xcafe010, End: 0xcafe020}},
				Children: []*InlineInfo{
					{
						Name:     w.AddString("malloc"),
						CallFile: 0,
						CallLine: 0,
						Ranges:   []AddressRange{{Start: 0xcafe015, End: 0xcafe016}},
						Children: nil,
					},
				},
			},

			{
				Name:     w.AddString("inline3"),
				CallFile: 0,
				CallLine: 0,
				Ranges:   []AddressRange{{Start: 0xcafe030, End: 0xcafe040}},
				Children: nil,
			},
		},
	}
	w.AddFuncInfo(FunctionInfo{
		Addr:       0xcafe000,
		Size:       0x100,
		Name:       w.AddString("inline1"),
		InlineInfo: ii,
	})

	dir := t.TempDir()
	f, err := os.Create(filepath.Join(dir, "test.gsym"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	err = w.Encode(f)
	require.NoError(t, err)
	_, err = f.Seek(0, io.SeekStart)
	require.NoError(t, err)
	reader, err := NewGsymWithReader(f)
	require.NoError(t, err)

	testdata := []struct {
		addr  uint64
		names []string
	}{
		{0xef, []string{"main.main"}},
		{0xef + 0x10 - 1, []string{"main.main"}},
		{0xef + 0x10, []string{}},
		{0xef + 0x11, []string{}},
		{0x200, []string{"main.foo"}},
		{0x200 + 0x20, []string{}},
		{0x200 + 0x21, []string{}},
		{0xcafe000, []string{"inline1"}},
		{0xcafe010, []string{"inline2", "inline1"}},
		{0xcafe011, []string{"inline2", "inline1"}},
		{0xcafe015, []string{"malloc", "inline2", "inline1"}},
	}
	for _, testdatum := range testdata {
		t.Run(fmt.Sprintf("test_%x", testdatum.addr), func(t *testing.T) {
			address, err := reader.LookupAddress(testdatum.addr)
			actual := []string{}
			for _, loc := range address.Locations {
				actual = append(actual, loc.Name)
			}
			if len(testdatum.names) == 0 {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, testdatum.names, actual)
			}
		})
	}
}

func TestEmptyWriterEncode(t *testing.T) {
	d := t.TempDir()
	f, err := os.Create(filepath.Join(d, "test.gsym"))
	require.NoError(t, err)
	w := NewWriter()
	err = w.Encode(f)
	require.NoError(t, err)
}
