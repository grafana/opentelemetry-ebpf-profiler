package amd

import (
	"io"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"golang.org/x/arch/x86/x86asm"
)

type VirtualMemory interface {
	VirtualMemory(addr int64, sz, maxSize int) ([]byte, error)
}

// todo plug this into the interpreter
type Disassembler struct {
	mem     VirtualMemory
	bufSize int
	rip     libpf.Address
	end     libpf.Address
	code    []byte
}

const minInstructionLength = 15

func NewSymbolDisassembler(mem VirtualMemory, sym *libpf.Symbol) *Disassembler {
	return NewDisassembler(
		mem,
		libpf.Address(sym.Address),
		libpf.Address(uint64(sym.Address)+sym.Size),
	)
}

func NewDisassembler(mem VirtualMemory, start libpf.Address, end libpf.Address) *Disassembler {
	return &Disassembler{
		mem:     mem,
		rip:     start,
		end:     end,
		bufSize: 0x1000,
	}
}

func (d *Disassembler) Next() (x86asm.Inst, libpf.Address, error) {
	if len(d.code) < minInstructionLength {
		if err := d.pull(); err != nil {
			return x86asm.Inst{}, d.rip, err
		}
	}
	inst, err := d.next()
	return inst, d.rip, err
}

func (d *Disassembler) pull() error {

	//todo this does pull 15 times for the last 15 bytes? can we avoid
	if d.rip >= d.end {
		return io.EOF
	}
	sz := d.bufSize
	if sz < minInstructionLength {
		sz = minInstructionLength
	}
	rem := int(d.end - d.rip)
	if sz > rem {
		sz = rem
	}
	var err error
	d.code, err = d.mem.VirtualMemory(int64(d.rip), sz, sz)
	if err != nil {
		return err
	}
	return nil
}

func (d *Disassembler) next() (inst x86asm.Inst, err error) {
	if len(d.code) == 0 {
		return x86asm.Inst{}, io.EOF
	}
	if ok, l := DecodeSkippable(d.code); ok {
		inst = x86asm.Inst{Op: x86asm.NOP, Len: l}
	} else {
		inst, err = x86asm.Decode(d.code, 64)
		if err != nil {
			return inst, err
		}
	}
	d.rip += libpf.Address(inst.Len)
	d.code = d.code[inst.Len:]
	return inst, err
}
