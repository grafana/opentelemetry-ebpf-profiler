package python

import (
	"cmp"
	"errors"
	"slices"

	"go.opentelemetry.io/ebpf-profiler/asm/amd"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/util"
	"golang.org/x/arch/x86/x86asm"
)

func FindJumpToColdRange(ef *pfelf.File, start util.Range) (uint64, error) {
	var (
		codeLen = int(start.End - start.Start)
		code    = make([]byte, codeLen)
		err     error
		inst    x86asm.Inst
		rip     = start.Start
	)

	n, err := ef.ReadAt(code, int64(start.Start))
	if err != nil {
		return 0, err
	}
	if n != len(code) {
		return 0, errors.New("read truncated code")
	}

	for len(code) > 0 {
		if ok, l := amd.DecodeSkippable(code); ok {
			inst = x86asm.Inst{Op: x86asm.NOP, Len: l}
		} else {
			inst, err = x86asm.Decode(code, 64)
			if err != nil {
				return 0, err
			}
		}

		//fmt.Printf("%8x %s\n", rip, x86asm.IntelSyntax(inst, rip, nil))
		rip += uint64(inst.Len)
		code = code[inst.Len:]
		if !isJump(inst.Op) {
			continue
		}
		if rel, ok := inst.Args[0].(x86asm.Rel); !ok {
			continue
		} else {
			dst := uint64(int64(rip) + int64(rel))
			if dst >= start.Start && dst < start.End {
				continue
			}
			return dst, nil
		}
	}
	return 0, nil
}

func isJump(op x86asm.Op) bool {
	switch op {
	case x86asm.JA,
		x86asm.JAE,
		x86asm.JB,
		x86asm.JBE,
		x86asm.JCXZ,
		x86asm.JE,
		x86asm.JECXZ,
		x86asm.JG,
		x86asm.JGE,
		x86asm.JL,
		x86asm.JLE,
		x86asm.JMP,
		x86asm.JNE,
		x86asm.JNO,
		x86asm.JNP,
		x86asm.JNS,
		x86asm.JO,
		x86asm.JP,
		x86asm.JRCXZ,
		x86asm.JS:
		return true
	default:
		return false
	}
}

func sortRanges(res []util.Range) {
	slices.SortFunc(res, func(a, b util.Range) int {
		return cmp.Compare(a.Start, b.Start)
	})
}
