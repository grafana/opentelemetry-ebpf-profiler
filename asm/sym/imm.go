// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package sym // import "go.opentelemetry.io/ebpf-profiler/asm/sym"
import "fmt"

func Imm(v uint64) U64 {
	return immediate{v}
}

type immediate struct {
	Value uint64
}

func (v immediate) Simplify() U64 {
	return v
}

func (v immediate) String() string {
	return fmt.Sprintf("0x%x", v.Value)
}

func (v immediate) Eval(other U64) bool {
	switch typed := other.(type) {
	case immediate:
		return v.Value == typed.Value
	case *Variable:
		typed.ExtractedValue = v.Value
		return true
	default:
		return false
	}
}
