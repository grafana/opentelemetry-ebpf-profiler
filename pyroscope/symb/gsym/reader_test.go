package gsym

import (
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/stretchr/testify/assert"
)

func TestHeaderParsing(t *testing.T) {
	f, err := os.Open("../testdata/inlineapp.gsym")
	require.NoError(t, err)
	defer f.Close()

	g, err := NewGsymWithReader(f)
	require.NoError(t, err)

	assert.Equal(t, Magic, g.Header.Magic)
	assert.Equal(t, uint16(0x0001), g.Header.Version)
	assert.Equal(t, uint8(0x02), g.Header.AddrOffSize)
	assert.Equal(t, uint8(0x10), g.Header.UUIDSize)
	assert.Equal(t, uint64(0x100000000), g.Header.BaseAddress)
	assert.Equal(t, uint32(0x00000008), g.Header.NumAddresses)
	assert.Equal(t, uint32(0x0000008c), g.Header.StrtabOffset)
	assert.Equal(t, uint32(0x000001de), g.Header.StrtabSize)
	assert.Equal(t, "6245042154203af087ca010fc8d6ceba", g.Header.UUIDString())
	assert.Equal(t, int64(48), g.Header.Size())
}

func TestGetAddressIndex(t *testing.T) {
	f, err := os.Open("../testdata/inlineapp.gsym")
	require.NoError(t, err)

	defer f.Close()

	g, err := NewGsymWithReader(f)
	require.NoError(t, err)

	idx, err := g.GetTextRelativeAddressIndex(0x308b)
	assert.Equal(t, ErrAddressNotFound, err)
	assert.Equal(t, 0, idx)

	idx, err = g.GetTextRelativeAddressIndex(0x308c)
	require.NoError(t, err)
	assert.Equal(t, 0, idx)

	idx, err = g.GetTextRelativeAddressIndex(0x308d)
	require.NoError(t, err)
	assert.Equal(t, 0, idx)

	idx, err = g.GetTextRelativeAddressIndex(0x30d4)
	require.NoError(t, err)
	assert.Equal(t, 1, idx)

	idx, err = g.GetTextRelativeAddressIndex(0x32b4)
	require.NoError(t, err)
	assert.Equal(t, 7, idx)

	idx, err = g.GetTextRelativeAddressIndex(0x32b5)
	require.NoError(t, err)
	assert.Equal(t, 7, idx)
}

func TestGetAddressInfo(t *testing.T) {
	f, err := os.Open("../testdata/inlineapp.gsym")
	require.NoError(t, err)

	defer f.Close()

	g, err := NewGsymWithReader(f)
	require.NoError(t, err)

	off, err := g.GetAddressInfoOffset(7)
	require.NoError(t, err)
	assert.Equal(t, int64(0x410), off)
}

func TestLookupAddress(t *testing.T) {
	f, err := os.Open("../testdata/inlineapp.gsym")
	require.NoError(t, err)

	defer f.Close()

	g, err := NewGsymWithReader(f)
	require.NoError(t, err)

	lr, err := g.LookupTextRelativeAddress(0x3177)
	require.NoError(t, err)

	assert.Equal(t, uint64(0x3177), lr.Address)
	assert.Equal(t, uint64(0x314c), lr.StartAddr)
	assert.Equal(t, uint64(0x38), lr.Size)
	assert.Equal(t, "main", lr.Name)

	require.Len(t, lr.Locations, 1)

	assert.Equal(t, "main", lr.Locations[0].Name)
	assert.Equal(t, uint32(14), lr.Locations[0].Line)
	assert.Equal(t, uint32(43), lr.Locations[0].Offset)
}

func TestLookupAddressWithInlineInfo(t *testing.T) {
	f, err := os.Open("../testdata/inlineapp.gsym")
	require.NoError(t, err)
	defer f.Close()

	g, err := NewGsymWithReader(f)
	require.NoError(t, err)

	lr, err := g.LookupTextRelativeAddress(0x32b3)
	require.NoError(t, err)

	assert.Equal(t, uint64(0x32b3), lr.Address)
	assert.Equal(t, uint64(0x3274), lr.StartAddr)
	assert.Equal(t, uint64(0x40), lr.Size)
	assert.Equal(t, "__45-[AppDelegate applicationDidFinishLaunching:]_block_invoke", lr.Name)

	require.Len(t, lr.Locations, 3)

	loc := lr.Locations[0]
	assert.Equal(t, "functionB", loc.Name)
	assert.Equal(t, uint32(14), loc.Line)
	assert.Equal(t, uint32(31), loc.Offset)

	loc = lr.Locations[1]
	assert.Equal(t, "functionA", loc.Name)
	assert.Equal(t, uint32(18), loc.Line)
	assert.Equal(t, uint32(31), loc.Offset)

	loc = lr.Locations[2]
	assert.Equal(t, "__45-[AppDelegate applicationDidFinishLaunching:]_block_invoke", loc.Name)
	assert.Equal(t, uint32(33), loc.Line)
	assert.Equal(t, uint32(63), loc.Offset)
}

func TestLookupAddressInFunctionWithInlineInfo(t *testing.T) {
	f, err := os.Open("../testdata/inlineapp.gsym")
	require.NoError(t, err)
	defer f.Close()

	g, err := NewGsymWithReader(f)
	require.NoError(t, err)

	lr, err := g.LookupTextRelativeAddress(0x3291)
	require.NoError(t, err)

	assert.Equal(t, uint64(0x3291), lr.Address)
	assert.Equal(t, uint64(0x3274), lr.StartAddr)
	assert.Equal(t, uint64(0x40), lr.Size)
	assert.Equal(t, "__45-[AppDelegate applicationDidFinishLaunching:]_block_invoke", lr.Name)

	if assert.Len(t, lr.Locations, 1) == false {
		return
	}

	loc := lr.Locations[0]
	assert.Equal(t, "__45-[AppDelegate applicationDidFinishLaunching:]_block_invoke", loc.Name)
	assert.Equal(t, uint32(31), loc.Line)
	assert.Equal(t, uint32(29), loc.Offset)
}

func TestLookupAddressInGSYMWithoutLineTables(t *testing.T) {
	f, err := os.Open("../testdata/CFNetwork.gsym")
	require.NoError(t, err)
	defer f.Close()

	g, err := NewGsymWithReader(f)
	require.NoError(t, err)

	assert.Equal(t, uint64(0x180a4e000), g.Header.BaseAddress)
	assert.Equal(t, "9c2d6e302482364380a345930c02edc0", g.Header.UUIDString())

	// inside CFURLRequestCreate
	lr, err := g.LookupAddress(0x0000000180ab303e)
	require.NoError(t, err)

	require.Len(t, lr.Locations, 1)

	loc := lr.Locations[0]
	assert.Equal(t, "CFURLRequestCreate", loc.Name)
	assert.Equal(t, uint32(0), loc.Line)
	assert.Equal(t, uint32(2), loc.Offset)
}

func TestLibcGSYMUtils(t *testing.T) {
	///usr/lib/llvm-18/bin/llvm-gsymutil --convert=./libc.debug --out-file=libc-gsymutil.gsym
	f, err := os.Open("../testdata/libc-gsymutil.gsym")
	require.NoError(t, err)
	defer f.Close()
	r, err := NewGsymWithReader(f)
	require.NoError(t, err)

	check := func(expected []string, addr uint64) {
		res, err2 := r.LookupAddress(addr)
		require.NoError(t, err2)
		actual := []string{}
		for _, location := range res.Locations {
			actual = append(actual, location.Name)
		}
		assert.Equal(t, expected, actual)
	}
	check([]string{"__GI___libc_read"}, 0x11ba61)
	check([]string{"__memcmp_avx2_movbe"}, 0x18833e)
	check([]string{"start_thread"}, 0x9ca94)
	check([]string{"clone3"}, 0x129c3c)
	check([]string{"__GI___futex_abstimed_wait_cancelable64"}, 0x98d61) // todo: why no inline info?
	check([]string{"___pthread_cond_timedwait64"}, 0x9bc7e)             // todo: why no inline info?
}

func TestLibcGSYMSymb(t *testing.T) {
	///usr/lib/llvm-18/bin/llvm-gsymutil --convert=./libc.debug --out-file=libc-gsymutil.gsym
	r := convert(t, "../testdata/libc.debug")

	check := func(expected []string, addr uint64) {
		res, err2 := r.LookupAddress(addr)
		require.NoError(t, err2)
		actual := []string{}
		for _, location := range res.Locations {
			actual = append(actual, location.Name)
		}
		assert.Equal(t, expected, actual)
	}
	check([]string{"__GI___libc_read"}, 0x11ba61)
	check([]string{"__memcmp_avx2_movbe"}, 0x18833e)
	check([]string{"start_thread"}, 0x9ca94)
	check([]string{"__clone3"}, 0x129c3c)
	check([]string{"__futex_abstimed_wait_common64", "__futex_abstimed_wait_common",
		"__GI___futex_abstimed_wait_cancelable64"}, 0x98d61)
	check([]string{"__pthread_cond_wait_common", "___pthread_cond_timedwait64"}, 0x9bc7e)
}

func BenchmarkGsymSymb(b *testing.B) {
	r := convert(b, "../testdata/libc.debug")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = r.LookupAddress(0x11ba61)
		_, _ = r.LookupAddress(0x18833e)
		_, _ = r.LookupAddress(0x9ca94)
		_, _ = r.LookupAddress(0x129c3c)
		_, _ = r.LookupAddress(0x98d61)
		_, _ = r.LookupAddress(0x9bc7e)
	}
}

func convert(b testing.TB, f string) *Gsym {
	ff, err := os.Open(f)
	require.NoError(b, err)
	defer ff.Close()
	outd := b.TempDir()
	out, err := os.Create(outd + "/libc.gsym")
	require.NoError(b, err)
	err = FDToGSym(ff, out)
	require.NoError(b, err)

	_, err = out.Seek(0, io.SeekStart)
	require.NoError(b, err)

	r, err := NewGsymWithReader(out)
	require.NoError(b, err)
	return r
}

func TestLongString(t *testing.T) {
	addr := 31396750
	r, err := os.Open("../testdata/e864973d50cb1d990a021fa22c680a7e.gsym")
	require.NoError(t, err)
	defer r.Close()
	g, err := NewGsymWithReader(r)
	require.NoError(t, err)
	res, err := g.LookupTextRelativeAddress(uint64(addr))
	require.NoError(t, err)
	//nolint:lll
	const expected = "connectrpc.com/connect.NewUnaryHandler[go.shape.struct { github.com/grafana/pyroscope/api/gen/proto/go/push/v1.state google.golang.org/protobuf/internal/impl.MessageState; github.com/grafana/pyroscope/api/gen/proto/go/push/v1.sizeCache int32; github.com/grafana/pyroscope/api/gen/proto/go/push/v1.unknownFields []uint8; Series []*github.com/grafana/pyroscope/api/gen/proto/go/push/v1.RawProfileSeries \"protobuf:\\\"bytes,1,rep,name=series,proto3\\\" json:\\\"series,omitempty\\\"\" },go.shape.struct { github.com/grafana/pyroscope/api/gen/proto/go/push/v1.state google.golang.org/protobuf/internal/impl.MessageState; github.com/grafana/pyroscope/api/gen/proto/go/push/v1.sizeCache int32; github.com/grafana/pyroscope/api/gen/proto/go/push/v1.unknownFields []uint8 }].func1"
	require.Equal(t, expected, res.Name)
}
