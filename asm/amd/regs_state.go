// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package amd // import "go.opentelemetry.io/ebpf-profiler/asm/amd"

import (
	"errors"
	"fmt"
	"go.opentelemetry.io/ebpf-profiler/asm/sym"
	"golang.org/x/arch/x86/x86asm"
	"io"
	"math"
)

// regIndex returns index into RegsState.regs
func regIndex(reg x86asm.Reg) int {
	switch reg {
	case x86asm.RAX, x86asm.EAX:
		return 1
	case x86asm.RBX, x86asm.EBX:
		return 2
	case x86asm.RCX, x86asm.ECX:
		return 3
	case x86asm.RDX, x86asm.EDX:
		return 4
	case x86asm.RDI, x86asm.EDI:
		return 5
	case x86asm.RSI, x86asm.ESI:
		return 6
	case x86asm.RBP, x86asm.EBP:
		return 7
	case x86asm.R8, x86asm.R8L:
		return 8
	case x86asm.R9, x86asm.R9L:
		return 9
	case x86asm.R10, x86asm.R10L:
		return 10
	case x86asm.R11, x86asm.R11L:
		return 11
	case x86asm.R12, x86asm.R12L:
		return 12
	case x86asm.R13, x86asm.R13L:
		return 13
	case x86asm.R14, x86asm.R14L:
		return 14
	case x86asm.R15, x86asm.R15L:
		return 15
	case x86asm.RSP, x86asm.ESP:
		return 16
	case x86asm.RIP:
		return 17
	default:
		return 0
	}
}

type RegsState[T interface {
	comparable
	fmt.Stringer
}] struct {
	regs [18]T
}

func (r *RegsState[T]) Set(reg x86asm.Reg, v T) {
	if reg != x86asm.RIP {
		fmt.Printf("                               -> | %6s = %s\n", reg, v.String())
	}
	r.regs[regIndex(reg)] = v
}

func (r *RegsState[T]) Get(reg x86asm.Reg) T {
	return r.regs[regIndex(reg)]
}

func (r *RegsState[T]) Reset(v T) {
	for i := range r.regs {
		r.regs[i] = v
	}
}

type Interpreter struct {
	Regs        RegsState[sym.U64]
	code        []byte
	CodeAddress sym.U64
	pc          int
}

func NewInterpreter(code []byte) Interpreter {
	it := Interpreter{code: code, CodeAddress: sym.Symbol("code")}
	for i := 0; i < len(it.Regs.regs); i++ {
		it.Regs.regs[i] = sym.Symbol(fmt.Sprintf("sym reg %d", i))
	}
	return it
}

func (i *Interpreter) Loop(breakLoop func(op x86asm.Inst) bool) (x86asm.Inst, error) {
	for j := 0; j < 137; j++ {
		op, err := i.Step()
		if err != nil {
			return op, err
		}
		if breakLoop(op) {
			return op, nil
		}
	}
	return x86asm.Inst{}, errors.New("loop bound") // todo better error

}
func (i *Interpreter) Step() (x86asm.Inst, error) {
	rem := i.code[i.pc:]
	if len(rem) == 0 {
		return x86asm.Inst{}, io.EOF
	}
	if ok, insnLen := DecodeSkippable(rem); ok {
		i.pc += insnLen
		return x86asm.Inst{Op: x86asm.NOP}, nil
	}
	inst, err := x86asm.Decode(rem, 64)
	if err != nil {
		return x86asm.Inst{}, fmt.Errorf("failed to decode instruction at 0x%x : %w",
			i.pc, err)
	}
	fmt.Printf(" | %4x %s\n", i.pc, inst.String())
	i.pc += inst.Len
	i.Regs.Set(x86asm.RIP, sym.Add(i.CodeAddress, sym.Imm(uint64(i.pc))))

	if inst.Op == x86asm.RET {
		return inst, nil
	}
	if inst.Op == x86asm.ADD {
		if dst, ok := inst.Args[0].(x86asm.Reg); ok {
			switch src := inst.Args[1].(type) {
			case x86asm.Imm:
				i.Regs.Set(dst, sym.Add(i.Regs.Get(dst), sym.Imm(uint64(src))))
			case x86asm.Reg:
				i.Regs.Set(dst, sym.Add(i.Regs.Get(dst), i.Regs.Get(src)))
			case x86asm.Mem:
				vs := make([]sym.U64, 0, 3)
				if src.Disp != 0 {
					vs = append(vs, sym.Imm(uint64(src.Disp)))
				}
				if src.Base != 0 {
					vs = append(vs, i.Regs.Get(src.Base))
				}
				if src.Index != 0 {
					vs = append(vs, sym.Mul(i.Regs.Get(src.Index), sym.Imm(uint64(src.Scale))))
				}
				v := sym.Add(vs...)
				i.Regs.Set(dst, sym.Add(i.Regs.Get(dst), sym.MemS(src.Segment, v)))
				break
			}
		}
	}
	if inst.Op == x86asm.SHL {
		if dst, ok := inst.Args[0].(x86asm.Reg); ok {
			switch src := inst.Args[1].(type) {
			case x86asm.Imm:
				i.Regs.Set(dst, sym.Mul(i.Regs.Get(dst), sym.Imm(uint64(math.Pow(2, float64(src))))))
			}
		}
	}
	if inst.Op == x86asm.MOV {
		if dst, ok := inst.Args[0].(x86asm.Reg); ok {
			switch src := inst.Args[1].(type) {
			case x86asm.Imm:
				i.Regs.Set(dst, sym.Imm(uint64(src)))
			case x86asm.Reg:
				i.Regs.Set(dst, i.Regs.Get(src))
			case x86asm.Mem:
				vs := make([]sym.U64, 0, 3)
				if src.Disp != 0 {
					vs = append(vs, sym.Imm(uint64(src.Disp)))
				}
				if src.Base != 0 {
					vs = append(vs, i.Regs.Get(src.Base))
				}
				if src.Index != 0 {
					vs = append(vs, sym.Mul(i.Regs.Get(src.Index), sym.Imm(uint64(src.Scale))))
				}
				v := sym.Add(vs...)
				i.Regs.Set(dst, sym.MemS(src.Segment, v))
			}
		}
	}
	if inst.Op == x86asm.XOR {
		if dst, ok := inst.Args[0].(x86asm.Reg); ok {
			switch src := inst.Args[1].(type) {
			case x86asm.Reg:
				i.Regs.Set(dst, sym.Xor(i.Regs.Get(dst), i.Regs.Get(src)))
			}
		}
	}
	if inst.Op == x86asm.LEA {
		if dst, ok := inst.Args[0].(x86asm.Reg); ok {
			switch src := inst.Args[1].(type) {
			case x86asm.Mem:
				vs := make([]sym.U64, 0, 3)
				if src.Disp != 0 {
					vs = append(vs, sym.Imm(uint64(src.Disp)))
				}
				if src.Base != 0 {
					vs = append(vs, i.Regs.Get(src.Base))
				}
				if src.Index != 0 {
					vs = append(vs, sym.Mul(i.Regs.Get(src.Index), sym.Imm(uint64(src.Scale))))
				}
				v := sym.Add(vs...)
				i.Regs.Set(dst, v)
			}
		}
	}
	return inst, nil
}
