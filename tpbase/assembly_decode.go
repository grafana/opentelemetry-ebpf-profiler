// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tpbase // import "go.opentelemetry.io/ebpf-profiler/tpbase"

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"runtime"

	"go.opentelemetry.io/ebpf-profiler/asm/amd"
	"go.opentelemetry.io/ebpf-profiler/asm/variable"
	"golang.org/x/arch/x86/x86asm"

	ah "go.opentelemetry.io/ebpf-profiler/armhelpers"
	aa "golang.org/x/arch/arm64/arm64asm"
)

func arm64GetAnalyzers() []Analyzer {
	return []Analyzer{
		{"tls_set", AnalyzeTLSSetARM64},
	}
}

func x86GetAnalyzers() []Analyzer {
	return []Analyzer{
		{"x86_fsbase_write_task", AnalyzeX86fsbaseWriteTask},
		{"aout_dump_debugregs", AnalyzeAoutDumpDebugregsAmd64},
	}
}

// AnalyzeTLSSet looks at the assembly of the `tls_set` function in the
// kernel in order to compute the offset of `tp_value` into `task_struct`.
func AnalyzeTLSSetARM64(code []byte) (uint32, error) {
	// This tries to extract offset of thread.uw.tp_value relative to
	// struct task_struct. The code analyzed comes from:
	// linux/arch/arm64/kernel/ptrace.c: tls_set(struct task_struct *target, ...) {
	// [...]
	//  unsigned long tls = target->thread.uw.tp_value;
	//
	// Anyalysis is based on the fact that 'target' is in X0 at the start, and early
	// in the assembly there is a direct load via this pointer. Because of reduced
	// instruction set, the pointer often gets moved to another register before the
	// load we are interested, so the arg []bool tracks which register is currently
	// holding the tracked pointer. Once a proper load is matched, the offset is
	// extracted from it.

	// Start tracking of X0
	var arg [32]bool
	arg[0] = true

	for offs := 0; offs < len(code); offs += 4 {
		inst, err := aa.Decode(code[offs:])
		if err != nil {
			break
		}
		if inst.Op == aa.B {
			break
		}

		switch inst.Op {
		case aa.MOV:
			// Track register moves
			destReg, ok := ah.Xreg2num(inst.Args[0])
			if !ok {
				continue
			}
			if srcReg, ok := ah.Xreg2num(inst.Args[1]); ok {
				arg[destReg] = arg[srcReg]
			}
		case aa.LDR:
			// Track loads with offset of the argument pointer we care
			m, ok := inst.Args[1].(aa.MemImmediate)
			if !ok {
				continue
			}
			var srcReg int
			if srcReg, ok = ah.Xreg2num(m.Base); !ok || !arg[srcReg] {
				continue
			}
			// FIXME: m.imm is not public, but should be.
			// https://github.com/golang/go/issues/51517
			imm, ok := ah.DecodeImmediate(m)
			if !ok {
				return 0, err
			}
			// Quick sanity check. Per example, the offset should
			// be under 4k. But allow some leeway.
			if imm < 64 || imm >= 65536 {
				return 0, fmt.Errorf("detected tpbase %#x looks invalid", imm)
			}
			return uint32(imm), nil
		default:
			// Reset register state if something unsupported happens on it
			if destReg, ok := ah.Xreg2num(inst.Args[0]); ok {
				arg[destReg] = false
			}
		}
	}

	return 0, errors.New("tp base not found")
}

// AnalyzeAoutDumpDebugregs looks at the assembly of the `aout_dump_debugregs` function in the
// kernel in order to compute the offset of `fsbase` into `task_struct`.
func AnalyzeAoutDumpDebugregsAmd64(code []byte) (uint32, error) {
	if len(code) == 0 {
		return 0, errors.New("empty code blob passed to getFSBaseOffset")
	}
	it := amd.NewInterpreterWithCode(code)
	for j := 0; j < 137; j++ {
		op, err := it.Step()
		if err != nil {
			return 0, err
		}
		switch op.Op {
		case x86asm.MOV:
			if dst, ok := op.Args[0].(x86asm.Reg); ok {
				actual := it.Regs.Get(dst)
				offset := variable.Var("offset")
				expected := variable.Mem(
					variable.Add(
						variable.MemS(x86asm.GS, variable.Any(), 8),
						offset,
					),
					8,
				)
				if actual.Eval(expected) {
					res := int64(offset.ExtractedValue) - 2*8
					if res < 0 || res > math.MaxUint32 {
						return 0, errors.New("overflow") // todo better error
					}
					return uint32(res), nil
				}
			}
		default:
			continue
		}
	}
	return 0, errors.New("not found") // todo better error
}

// AnalyzeX86fsbaseWriteTask looks at the assembly of the function x86_fsbase_write_task which
// is ideal because it only writes the argument to the fsbase function. We can get the fsbase
// offset directly from the assembly here. Available since kernel version 4.20.
func AnalyzeX86fsbaseWriteTask(code []byte) (uint32, error) {
	// Supported sequences (might be surrounded be additional code for the WARN_ONCE):
	//
	// 1) Alpine Linux (kernel 5.10+)
	//    48 89 b7 XX XX XX XX 	mov    %rsi,0xXXXXXXXX(%rdi)

	// No need to disassemble via zydis here, as it's highly unlikely the below machine code
	// matching approach would fail. Indeed, x86-64 calling conventions ensure that:
	// * %rdi is a pointer to a `task_struct` (first parameter)
	// * %rsi == fsbase value (second parameter)
	// the x86_fsbase_write_task function simply sets that task (from the first parameter) fsbase to
	// be equal to the second parameter.
	// See https://elixir.bootlin.com/linux/latest/source/arch/x86/kernel/process_64.c#L466
	idx := bytes.Index(code, []byte{0x48, 0x89, 0xb7})
	if idx == -1 || idx+7 > len(code) {
		return 0, errors.New("unexpected x86_fsbase_write_task (mov not found)")
	}
	offset := binary.LittleEndian.Uint32(code[idx+3:])
	return offset, nil
}

func GetAnalyzers() ([]Analyzer, error) {
	switch runtime.GOARCH {
	case "arm64":
		return arm64GetAnalyzers(), nil
	case "amd64":
		return x86GetAnalyzers(), nil
	default:
		return nil, fmt.Errorf("unsupported arch %s", runtime.GOARCH)
	}
}
