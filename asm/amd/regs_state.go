// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package amd // import "go.opentelemetry.io/ebpf-profiler/asm/amd"

import (
	"fmt"
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
	case x86asm.RSP, x86asm.ESP:
		return 8
	case x86asm.RIP:
		return 9
	case x86asm.FS:
		return 10
	case x86asm.GS:
		return 11
	default:
		return 0
	}
}

type RegsState[T any] struct {
	regs [12]T
}

func (r *RegsState[T]) Set(reg x86asm.Reg, v T) {
	if reg != x86asm.RIP {
		fmt.Printf("                               -> | %6s = %s\n", reg, v)
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

type Interptreter struct {
	Regs        RegsState[U64]
	code        []byte
	CodeAddress U64
	pc          int
}

func NewInterpreter(code []byte) Interptreter {
	return Interptreter{code: code, CodeAddress: Sym{Name: "code"}}
}
func (i *Interptreter) Step() (x86asm.Op, error) {
	rem := i.code[i.pc:]
	if len(rem) == 0 {
		return 0, io.EOF
	}
	if endbr64, insnLen := IsEndbr64(rem); endbr64 {
		i.pc += insnLen
		return x86asm.NOP, nil
	}
	inst, err := x86asm.Decode(rem, 64)
	if err != nil {
		return 0, fmt.Errorf("failed to decode instruction at 0x%x : %w",
			i.pc, err)
	}
	fmt.Printf(" | %4x %s\n", i.pc, inst.String())
	i.pc += inst.Len
	i.Regs.Set(x86asm.RIP, Add(i.CodeAddress, Imm(uint64(i.pc))))

	if inst.Op == x86asm.RET {
		return inst.Op, nil
	}
	if inst.Op == x86asm.ADD {
		if dst, ok := inst.Args[0].(x86asm.Reg); ok {
			switch src := inst.Args[1].(type) {
			case x86asm.Imm:
				i.Regs.Set(dst, Add(i.Regs.Get(dst), Imm(uint64(src))))
			case x86asm.Reg:
				i.Regs.Set(dst, Add((&i.Regs).Get(dst), (&i.Regs).Get(src)))
			case x86asm.Mem:
				v := Add(
					Add((&i.Regs).Get(src.Base), Imm(uint64(src.Disp))),
					Mul((&i.Regs).Get(src.Index), Imm(uint64(src.Scale))),
				)
				(&i.Regs).Set(dst, Add((&i.Regs).Get(dst), MemS(src.Segment, v)))
				break
			}
		}
	}
	if inst.Op == x86asm.SHL {
		if dst, ok := inst.Args[0].(x86asm.Reg); ok {
			switch src := inst.Args[1].(type) {
			case x86asm.Imm:
				(&i.Regs).Set(dst, Mul((&i.Regs).Get(dst), Imm(uint64(math.Pow(2, float64(src))))))
			}
		}
	}
	if inst.Op == x86asm.MOV {
		if dst, ok := inst.Args[0].(x86asm.Reg); ok {
			switch src := inst.Args[1].(type) {
			case x86asm.Imm:
				(&i.Regs).Set(dst, Imm(uint64(src)))
			case x86asm.Reg:
				(&i.Regs).Set(dst, (&i.Regs).Get(src))
			case x86asm.Mem:
				v := Add(
					Add((&i.Regs).Get(src.Base), Imm(uint64(src.Disp))),
					Mul((&i.Regs).Get(src.Index), Imm(uint64(src.Scale))),
				)
				(&i.Regs).Set(dst, MemS(src.Segment, v))
			}
		}
	}
	if inst.Op == x86asm.LEA {
		if dst, ok := inst.Args[0].(x86asm.Reg); ok {
			switch src := inst.Args[1].(type) {
			case x86asm.Mem:
				v := Add(
					Add((&i.Regs).Get(src.Base), Imm(uint64(src.Disp))),
					Mul((&i.Regs).Get(src.Index), Imm(uint64(src.Scale))),
				)
				(&i.Regs).Set(dst, v)
			}
		}
	}
	//}
	return inst.Op, nil
}
