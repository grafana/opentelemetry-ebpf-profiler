// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package sym // import "go.opentelemetry.io/ebpf-profiler/asm/sym"

import (
	"fmt"
)

func Symbol(name string) *Variable {
	return &Variable{
		Name:           name,
		ExtractedValue: 0,
	}
}

type Variable struct {
	Name           string
	ExtractedValue uint64
}

func (v *Variable) Reset() {
	v.ExtractedValue = 0
}

func (v *Variable) Simplify() U64 {
	return v
}

func (v *Variable) String() string {
	return fmt.Sprintf("{ @%s }", v.Name)
}

func (v *Variable) Eval(other U64) bool {
	switch typed := other.(type) {
	case *Variable:
		return v == typed
	default:
		return false
	}
}
