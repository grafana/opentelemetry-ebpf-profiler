package table

import (
	"debug/elf"
	"fmt"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/pyroscope/symb/ffi"
	"os"
	"testing"
)

const ally = "/home/korniltsev/alloy"

func TestName(t *testing.T) {

	e, err := elf.Open(ally)
	require.NoError(t, err)
	symbols, err := e.Symbols()
	require.NoError(t, err)
	i := 0
	for _, symbol := range symbols {
		fmt.Printf("%16x | %6x %s\n", symbol.Value, symbol.Size, symbol.Name)
		i++
		if i > 100 {
			break
		}
	}
}

const gtblfile = "/home/korniltsev/p/opentelemetry-ebpf-profiler/pyroscope/symb/table/alloy.gtbl"

func TestCreateGtbl(t *testing.T) {
	executable, err := os.Open(ally)
	require.NoError(t, err)
	defer executable.Close()
	output, err := os.Create(gtblfile)
	require.NoError(t, err)
	defer output.Close()
	err = createTable(t, executable, output)
	require.NoError(t, err)
}

//40b560 |     66 internal/abi.(*IntArgRegBitmap).Get

//
// 1. download debug file from debuginfod
// 2. convert it to gtbl << not sure how to do this once among multiple query-fronted
// 3. cache gtbl to objstore

// for the poc we measure FAT profile (from database, strip line symbols) lookup locally

// todo do not reinvent the wheel
type bufferCloser struct {
	bs  []byte
	off int64
}

func (b *bufferCloser) Read(p []byte) (n int, err error) {
	res, err := b.ReadAt(p, b.off)
	b.off += int64(res)
	return res, err
}

func (b *bufferCloser) ReadAt(p []byte, off int64) (n int, err error) {
	copy(p, b.bs[off:])
	return len(p), nil
}

func (b *bufferCloser) Close() error {
	return nil
}

func TestReadGtbl(t *testing.T) {
	bs, err := os.ReadFile(gtblfile)
	require.NoError(t, err)
	var f ReaderAtCloser = &bufferCloser{bs, 0}
	path, err := OpenReader(f)
	require.NoError(t, err)
	lookup, err := path.Lookup(0x40b560)

	require.NoError(t, err)
	require.Len(t, lookup, 1)
	require.Equal(t, "internal/abi.(*IntArgRegBitmap).Get", lookup[0].FunctionName)
	defer path.Close()

}

func createTable(t *testing.T, executable, output *os.File, opt ...Option) error {
	sb := newStringBuilder()
	rb := newRangesBuilder()
	lb := newLineTableBuilder()
	rc := &rangeCollector{sb: sb, rb: rb, lb: lb}
	for _, o := range opt {
		o(&rc.opt)
	}
	e, err := elf.NewFile(executable)
	require.NoError(t, err)

	symbols, err := e.Symbols()
	require.NoError(t, err)
	for _, symbol := range symbols {
		rc.VisitRange(&ffi.GoRange{
			VA:        symbol.Value,
			Length:    uint32(symbol.Size),
			Function:  symbol.Name,
			File:      "",
			CallFile:  "",
			CallLine:  0,
			Depth:     0,
			LineTable: nil,
		})
	}
	fmt.Printf("numbe of symbols %d\n", len(symbols))
	rb.sort()

	err2 := rc.write(output)
	if err2 != nil {
		return err2
	}

	return nil
}
