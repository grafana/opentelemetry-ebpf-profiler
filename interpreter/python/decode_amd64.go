// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package python // import "go.opentelemetry.io/ebpf-profiler/interpreter/python"

import (
	"fmt"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"golang.org/x/arch/x86/x86asm"
)

const debugDecodeAMD64 = false

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
	default:
		return 0
	}
}

type regState struct {
	loadedFrom uint64
	value      uint64
}

func decodeStubArgumentAMD64(code []byte, codeAddress uint64, memoryBase uint64) uint64 {
	targetRegister := x86asm.RDI

	instructionOffset := 0
	regs := [32]regState{}

	for instructionOffset < len(code) {
		if instructionOffset+4 <= len(code) &&
			code[instructionOffset] == 0xf3 &&
			code[instructionOffset+1] == 0x0f &&
			code[instructionOffset+2] == 0x1e &&
			code[instructionOffset+3] == 0xfa {
			if debugDecodeAMD64 {
				fmt.Printf("0x%x: endbr64 (special case)\n", codeAddress+uint64(instructionOffset))
			}
			instructionOffset += 4
			continue
		}

		inst, err := x86asm.Decode(code[instructionOffset:], 64)
		if err != nil {
			if debugDecodeAMD64 {
				fmt.Printf("Error decoding instruction at offset %d: %v\n", instructionOffset, err)
			}
			break
		}

		if debugDecodeAMD64 {
			fmt.Printf("0x%x: %s\n", codeAddress+uint64(instructionOffset), inst.String())
		}

		instructionOffset += inst.Len
		regs[regIndex(x86asm.RIP)].value = codeAddress + uint64(instructionOffset)

		if inst.Op == x86asm.CALL || inst.Op == x86asm.JMP {
			targetRegIdx := regIndex(targetRegister)
			if regs[targetRegIdx].loadedFrom != 0 {
				return regs[targetRegIdx].loadedFrom
			}
			return regs[targetRegIdx].value
		}

		if (inst.Op == x86asm.LEA || inst.Op == x86asm.MOV) && inst.Args[0] != nil {
			if reg, ok := inst.Args[0].(x86asm.Reg); ok {
				regIdx := regIndex(reg)
				var value uint64
				var loadedFrom uint64

				switch src := inst.Args[1].(type) {
				case x86asm.Imm:
					value = uint64(src)
				case x86asm.Mem:
					baseReg := src.Base
					baseAddr := regs[regIndex(baseReg)].value
					displacement := uint64(src.Disp)

					if baseReg == x86asm.RIP {
						baseAddr = codeAddress + uint64(instructionOffset)
					}

					if inst.Op == x86asm.MOV {
						value = memoryBase
						loadedFrom = baseAddr + displacement
					} else if inst.Op == x86asm.LEA {
						value = baseAddr + displacement
					}

					if src.Index != 0 {
						indexValue := regs[regIndex(src.Index)].value
						value += indexValue * uint64(src.Scale)
						if debugDecodeAMD64 {
							fmt.Printf("  Adding scaled index: index=%s (0x%x) * scale=%d = 0x%x\n",
								src.Index, indexValue, src.Scale, indexValue*uint64(src.Scale))
							fmt.Printf("  Updated value: 0x%x\n", value)
						}
					}

				case x86asm.Reg:
					value = regs[regIndex(src)].value
				}

				if debugDecodeAMD64 {
					fmt.Printf("  Setting register %s: value=0x%x, loaded from=0x%x\n", reg, value, loadedFrom)
				}

				regs[regIdx].value = value
				regs[regIdx].loadedFrom = loadedFrom
			}
		}

		if inst.Op == x86asm.ADD && inst.Args[0] != nil && inst.Args[1] != nil {
			if reg, ok := inst.Args[0].(x86asm.Reg); ok {
				if _, ok := inst.Args[1].(x86asm.Mem); ok {
					regIdx := regIndex(reg)
					oldValue := regs[regIdx].value
					value := oldValue + memoryBase
					regs[regIdx].value = value
					regs[regIdx].loadedFrom = 0
				}
			}
		}
	}
	return 0
}

func decodeStubArgumentWrapper(
	code []byte,
	codeAddress libpf.SymbolValue,
	memoryBase libpf.SymbolValue,
) libpf.SymbolValue {
	if len(code) == 0 {
		return 0
	}
	return libpf.SymbolValue(
		decodeStubArgumentAMD64(code, uint64(codeAddress), uint64(memoryBase)),
	)
}
