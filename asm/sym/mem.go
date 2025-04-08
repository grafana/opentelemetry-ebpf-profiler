// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package sym // import "go.opentelemetry.io/ebpf-profiler/asm/sym"

import (
	"fmt"
	"golang.org/x/arch/x86/x86asm"
)

func MemS(segment x86asm.Reg, at U64) U64 {
	return mem{at: at.Simplify(), segment: segment}
}
func Mem(at U64) U64 {
	return mem{at: at.Simplify(), segment: 0}
}

type mem struct {
	segment x86asm.Reg
	at      U64
}

func (v mem) Simplify() U64 {
	v.at = v.at.Simplify()
	return v
}

func (v mem) String() string {
	if v.segment == 0 {
		return fmt.Sprintf("[ %s ]", v.at.String())
	}
	return fmt.Sprintf("[ %s:%s ]", v.segment, v.at.String())
}

func (v mem) Eval(other U64) bool {
	switch typed := other.(type) {
	case mem:
		if v.segment != typed.segment {
			return false
		}
		return v.at.Eval(typed.at)
	default:
		return false
	}
}
