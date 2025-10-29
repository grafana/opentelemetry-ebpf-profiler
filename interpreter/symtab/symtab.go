package symtab

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"slices"
	"sort"
	"sync/atomic"

	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
)

func Loader(_ interpreter.EbpfHandler, info *interpreter.LoaderInfo) (
	interpreter.Data, error) {
	name := fmt.Sprintf("%s %s", info.FileName(), info.FileID().StringNoQuotes())

	return load(info.Reference(), name)
}

func load(ref *pfelf.Reference, name string) (interpreter.Data, error) {
	ef, err := ref.GetELF()
	if err != nil {
		return nil, err
	}

	debugFileName := ef.DebuglinkFileName(ref.FileName(), ref)
	if debugFileName != "" {
		debugElf, err := ref.OpenELF(debugFileName)
		if err == nil {
			ef = debugElf
			defer debugElf.Close()
		}
	}
	if err = ef.LoadSections(); err != nil {
		return nil, err
	}
	if ef.IsGolang() {
		return nil, nil
	}

	tables := make([]*symtab, 0, 2)
	for i, s := range ef.Sections {
		if s.Type == elf.SHT_SYMTAB || s.Type == elf.SHT_DYNSYM {
			symbols, err := ef.Sections[i].Data(uint(s.FileSize))
			if err != nil {
				return nil, err
			}
			ls := ef.Sections[s.Link]
			link, err := ls.Data(uint(ls.FileSize))
			if err != nil {
				return nil, err
			}
			tables = append(tables, &symtab{symbols: symbols, link: link, name: name})
		}
	}
	if len(tables) == 0 {
		return nil, nil
	}

	d := &data{
		ref:         ef.Take(),
		setDontNeed: ef.SetDontNeed,
		tables:      tables,
		name:        name,
	}
	d.refs.Add(1)
	return d, nil
}

func (s *data) Attach(ebpf interpreter.EbpfHandler, pid libpf.PID, bias libpf.Address, rm remotememory.RemoteMemory) (interpreter.Instance, error) {
	s.refs.Add(1)
	return &instance{d: s, pid: int(pid)}, nil
}

func (s *data) Unload(ebpf interpreter.EbpfHandler) {
	s.unref()

}

type data struct {
	refs atomic.Int32

	ref         io.Closer
	setDontNeed func()
	tables      []*symtab
	name        string
}

func (d *data) unref() {
	if d.refs.Add(-1) == 0 {
		_ = d.ref.Close()
		for _, t := range d.tables {
			loaded.Add(-int64(len(t.pc)))
		}
	}
}

type instance struct {
	interpreter.InstanceStubs
	pid int
	d   *data
}

func (i *instance) Detach(ebpf interpreter.EbpfHandler, pid libpf.PID) error {
	i.d.unref()
	return nil
}

func (i *instance) Symbolize(ebpfFrame *host.Frame, frames *libpf.Frames) error {
	if ebpfFrame.Type != libpf.NativeFrame {
		return interpreter.ErrMismatchInterpreterType
	}
	n := i.d.symbolize(uint64(ebpfFrame.Lineno))
	if n == "" {
		return interpreter.ErrMismatchInterpreterType
	}
	frames.Append(&libpf.Frame{
		Type:            libpf.GoFrame, //todo
		AddressOrLineno: ebpfFrame.Lineno,
		FunctionName:    libpf.Intern(n),
	})
	return nil
}

func (d *data) symbolize(addr uint64) string {
	n := ""
	for _, t := range d.tables {
		n = t.symbolize(uint64(addr))
		if n == "" {
			continue
		}
		//fmt.Printf("symbolize %s %x %s\n", d.name, addr, n)
		break
	}
	return n
}

func (i *instance) ReleaseResources() error {
	i.d.setDontNeed()
	return nil
}

type symtab struct {
	initialized bool

	name string

	symbols []byte
	link    []byte

	pc  []uint32
	idx []uint32
}

func (it *symtab) sym(i int) elf.Sym64 {
	rawSym := it.symbols[i*elf.Sym64Size : (i+1)*elf.Sym64Size]
	return elf.Sym64{
		Name:  binary.LittleEndian.Uint32(rawSym[:4]),
		Info:  rawSym[4],
		Value: binary.LittleEndian.Uint64(rawSym[8:16]),
		Size:  binary.LittleEndian.Uint64(rawSym[16:24]),
	}
}

func (it *symtab) init() {
	nn := len(it.symbols) / elf.Sym64Size
	n := 0
	it.pc = make([]uint32, nn)
	it.idx = make([]uint32, nn)
	for i := 1; i < nn; i++ {
		s := it.sym(i)
		if s.Value != 0 && s.Info&0xf == byte(elf.STT_FUNC) {
			it.pc[n] = uint32(s.Value)
			it.idx[n] = uint32(i)
			//debugName := it.symName(s)
			//fmt.Printf("symtab %s %x-%x %s\n", it.name, s.Value, s.Value+s.Size, debugName)
			n++
		}
	}
	it.pc = it.pc[:n]
	it.idx = it.idx[:n]
	sort.Sort(&sortPC{it.pc, it.idx})
	loaded.Add(int64(n))
	fmt.Printf("loaded %s %d symbol. total %d bytes\n", it.name, n, loaded.Load()*4*2)
}

type sortPC struct {
	pc  []uint32
	idx []uint32
}

func (s *sortPC) Len() int {

	return len(s.pc)
}

func (s *sortPC) Less(i, j int) bool {
	return s.pc[i] < s.pc[j]
}

func (s *sortPC) Swap(i, j int) {
	s.pc[i], s.pc[j] = s.pc[j], s.pc[i]
	s.idx[i], s.idx[j] = s.idx[j], s.idx[i]
}

var loaded atomic.Int64

func (it *symtab) symbolize(addr uint64) string {
	if !it.initialized {
		it.init()
		it.initialized = true
	}
	idx := it.findSymbolIndex(addr)
	if idx < 0 {
		return ""
	}
	s := it.sym(idx)
	if addr >= s.Value+s.Size {
		return ""
	}
	return it.symName(s.Name)
}

func (it *symtab) symName(sname uint32) string {
	if int(sname) >= len(it.link) {
		return ""
	}
	name := it.link[sname:]
	nameEnd := bytes.IndexByte(name, 0)
	if nameEnd == -1 {
		return ""
	}
	return string(name[:nameEnd])
}

func (it *symtab) findSymbolIndex(addr uint64) int {
	if len(it.pc) == 0 {
		return -1
	}
	if addr < uint64(it.pc[0]) {
		return -1
	}
	i, found := slices.BinarySearch(it.pc, uint32(addr))
	if found {
		return int(it.idx[i])
	}
	i--
	v := it.pc[i]
	for i > 0 && it.pc[i-1] == v {
		i--
	}
	return int(it.idx[i])
}
