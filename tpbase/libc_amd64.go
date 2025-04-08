// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tpbase // import "go.opentelemetry.io/ebpf-profiler/tpbase"

import (
	"errors"
	"go.opentelemetry.io/ebpf-profiler/asm/amd"
	_ "go.opentelemetry.io/ebpf-profiler/zydis" // links Zydis
	"golang.org/x/arch/x86/x86asm"
)

func ExtractTSDInfoX64_64(code []byte) (TSDInfo, error) {
	it := amd.NewInterpreter(code)
	key := amd.Sym{Name: "key"}
	it.Regs.Set(x86asm.RDI, key)
	it.Regs.Set(0, amd.Imm(0))

	for {
		op, err := it.Step()
		if err != nil {
			return TSDInfo{}, err
		}
		if op == x86asm.RET {
			break
		}
	}

	res := it.Regs.Get(x86asm.RAX)
	mul := amd.ImmediateExtractor{Value: new(uint64)}
	offset := amd.ImmediateExtractor{Value: new(uint64)}
	expected := amd.MemS(0, amd.Add(amd.Mem(amd.Add(amd.MemS(x86asm.FS, amd.Imm(0)), offset)), amd.Mul(key, mul)))
	ok := res.Match(expected)
	if ok {
		return TSDInfo{
			Offset:     int16(*offset.Value),
			Multiplier: uint8(*mul.Value),
			Indirect:   1,
		}, nil
	}
	*mul.Value = 0
	*offset.Value = 0
	expected = amd.Mem(amd.Add(amd.MemS(x86asm.FS, amd.Imm(0x10)), amd.Mul(key, mul), offset))
	ok = res.Match(expected)
	if ok {
		return TSDInfo{
			Offset:     int16(*offset.Value),
			Multiplier: uint8(*mul.Value),
			Indirect:   0,
		}, nil
	}
	return TSDInfo{}, errors.New("could not extract tsdInfo amd")
}

func ExtractTSDInfoNative(code []byte) (TSDInfo, error) {
	return ExtractTSDInfoX64_64(code)
}
