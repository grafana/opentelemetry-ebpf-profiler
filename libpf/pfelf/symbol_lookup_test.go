// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package pfelf

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/testsupport"
)

// symbolLookupFixture reuses the ELF fixture with both dynamic hash tables and
// .symtab. The returned bytes can be edited to exercise malformed symbol tables.
func symbolLookupFixture(t *testing.T) (*File, []byte, int, libpf.Symbol) {
	t.Helper()
	path, err := testsupport.WriteSharedLibrary()
	require.NoError(t, err)
	defer os.Remove(path)
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	reference, err := elf.NewFile(bytes.NewReader(raw))
	require.NoError(t, err)
	defer reference.Close()
	symbols, err := reference.Symbols()
	require.NoError(t, err)
	f, err := NewFile(bytes.NewReader(raw), 0, false)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, f.Close()) })
	for i, sym := range symbols {
		if sym.Name == "func" {
			// debug/elf omits the initial null entry from Symbols().
			offset := int(reference.Section(".symtab").Offset) + (i+1)*elf.Sym64Size
			return f, raw, offset, libpf.Symbol{
				Name: libpf.SymbolName(sym.Name), Address: libpf.SymbolValue(sym.Value),
				Size: sym.Size, Info: sym.Info, Shndx: uint16(sym.Section),
			}
		}
	}
	t.Fatal("func missing from fixture")
	return nil, nil, 0, libpf.Symbol{}
}

func TestLookupSymbolWithoutDynamicHash(t *testing.T) {
	fixture, raw, _, want := symbolLookupFixture(t)
	// Remove PT_DYNAMIC so opening the ELF finds neither dynamic hash table.
	for i, prog := range fixture.Progs {
		if prog.Type == elf.PT_DYNAMIC {
			offset := int(fixture.elfHeader.Phoff) + i*int(fixture.elfHeader.Phentsize)
			binary.LittleEndian.PutUint32(raw[offset:], uint32(elf.PT_NULL))
		}
	}
	f, err := NewFile(bytes.NewReader(raw), 0, false)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, f.Close()) })
	require.Zero(t, f.gnuHash.addr)
	require.Zero(t, f.sysvHash.addr)
	sym, err := f.LookupSymbol("func")
	require.NoError(t, err)
	require.Equal(t, want, *sym)
	address, err := f.LookupSymbolAddress("func")
	require.NoError(t, err)
	require.Equal(t, want.Address, address)
	_, code, err := f.SymbolData("func", 512)
	require.NoError(t, err)
	require.Len(t, code, int(want.Size))
	_, err = f.LookupSymbol("not_existent")
	require.ErrorIs(t, err, libpf.ErrSymbolNotFound)
}

func TestLookupSymbolStaticDefinitions(t *testing.T) {
	for _, tc := range []struct {
		name    string
		info    byte
		section uint16
		value   uint64
		found   bool
	}{
		{"undefined", elf.ST_INFO(elf.STB_GLOBAL, elf.STT_FUNC), uint16(elf.SHN_UNDEF), 0, false},
		{"undefined with value", elf.ST_INFO(elf.STB_GLOBAL, elf.STT_FUNC), uint16(elf.SHN_UNDEF), 1, false},
		{"local TLS at zero", elf.ST_INFO(elf.STB_LOCAL, elf.STT_TLS), 1, 0, true},
		{"global object", elf.ST_INFO(elf.STB_GLOBAL, elf.STT_OBJECT), 1, 0x19260e0, true},
		{"weak absolute at zero", elf.ST_INFO(elf.STB_WEAK, elf.STT_OBJECT), uint16(elf.SHN_ABS), 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, raw, offset, want := symbolLookupFixture(t)
			f.gnuHash.addr, f.sysvHash.addr = 0, 0
			raw[offset+4] = tc.info
			binary.LittleEndian.PutUint16(raw[offset+6:], tc.section)
			binary.LittleEndian.PutUint64(raw[offset+8:], tc.value)
			sym, err := f.LookupSymbol("func")
			if !tc.found {
				require.ErrorIs(t, err, libpf.ErrSymbolNotFound)
				require.Nil(t, sym)
				return
			}
			require.NoError(t, err)
			want.Info, want.Shndx, want.Address = tc.info, tc.section, libpf.SymbolValue(tc.value)
			require.Equal(t, want, *sym)
		})
	}
}

func TestLookupSymbolSkipsUndefinedStaticMatch(t *testing.T) {
	f, raw, offset, want := symbolLookupFixture(t)
	f.gnuHash.addr, f.sysvHash.addr = 0, 0
	first := int(f.Section(".symtab").Offset) + elf.Sym64Size
	require.Less(t, first, offset)
	// Place an undefined symbol with the same name before the definition.
	copy(raw[first:first+elf.Sym64Size], raw[offset:offset+elf.Sym64Size])
	binary.LittleEndian.PutUint16(raw[first+6:], uint16(elf.SHN_UNDEF))
	sym, err := f.LookupSymbol("func")
	require.NoError(t, err)
	require.Equal(t, want, *sym)
}

func TestLookupSymbolStaticTableErrors(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mutate  func(*File, *Section)
		message string
	}{
		{"no symtab", func(_ *File, s *Section) { s.Name = ".removed" }, "symbol hash not present"},
		{"no sections", func(f *File, _ *Section) {
			f.Sections, f.elfHeader.Shnum = nil, 0
		}, "symbol hash not present"},
		{"inside coredump", func(f *File, _ *Section) { f.InsideCore = true }, "symbol hash not present"},
		{"invalid link", func(f *File, s *Section) { s.Link = uint32(len(f.Sections)) }, "out of range"},
		{"wrong string table type", func(f *File, s *Section) {
			f.Sections[s.Link].Type = elf.SHT_PROGBITS
		}, "invalid section type"},
		{"unreadable string table", func(f *File, s *Section) {
			f.Sections[s.Link].Offset = 1 << 30
		}, "failed to read .strtab"},
		{"partial entry", func(_ *File, s *Section) { s.Size-- }, "invalid .symtab format"},
		{"wrong entry size", func(_ *File, s *Section) { s.Entsize = 1 }, "invalid .symtab format"},
		{"wrong table type", func(_ *File, s *Section) { s.Type = elf.SHT_PROGBITS }, "invalid .symtab format"},
		{"compressed table", func(_ *File, s *Section) { s.Flags |= elf.SHF_COMPRESSED }, "invalid .symtab format"},
		{"unreadable table", func(_ *File, s *Section) { s.Offset = 1 << 30 }, "failed to read symbol"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, _, _, _ := symbolLookupFixture(t)
			f.gnuHash.addr, f.sysvHash.addr = 0, 0
			table := f.Section(".symtab")
			require.NotNil(t, table)
			tc.mutate(f, table)
			sym, err := f.LookupSymbol("func")
			require.ErrorContains(t, err, tc.message)
			require.Nil(t, sym)
		})
	}
}

func TestLookupSymbolTruncatedStaticTable(t *testing.T) {
	for _, tc := range []struct {
		name string
		keep int
		err  error
	}{
		{"entry boundary", 0, io.EOF},
		{"partial entry", elf.Sym64Size - 1, io.ErrUnexpectedEOF},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, _, offset, _ := symbolLookupFixture(t)
			f.gnuHash.addr, f.sysvHash.addr = 0, 0
			// Keep the section headers and string table readable, but truncate the
			// symbol reader before it can read a complete definition of func.
			require.NoError(t, f.LoadSections())
			f.elfReader = io.NewSectionReader(f.elfReader, 0, int64(offset+tc.keep))
			sym, err := f.LookupSymbol("func")
			require.ErrorIs(t, err, tc.err)
			require.Nil(t, sym)
		})
	}
}

func TestLookupSymbolKeepsDynamicHashPriority(t *testing.T) {
	for _, hash := range []string{"GNU", "SysV"} {
		t.Run(hash, func(t *testing.T) {
			f, raw, offset, want := symbolLookupFixture(t)
			// A conflicting .symtab value must not override the dynamic definition.
			binary.LittleEndian.PutUint64(raw[offset+8:], 0xdeadbeef)
			if hash == "SysV" {
				f.gnuHash.addr = 0
			}
			sym, err := f.LookupSymbol("func")
			require.NoError(t, err)
			require.Equal(t, want, *sym)
			// _DYNAMIC is in .symtab only. Dynamic lookup semantics remain unchanged.
			_, err = f.LookupSymbol("_DYNAMIC")
			require.ErrorIs(t, err, libpf.ErrSymbolNotFound)
		})
	}
}
