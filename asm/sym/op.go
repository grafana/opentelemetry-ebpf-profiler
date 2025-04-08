// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package sym // import "go.opentelemetry.io/ebpf-profiler/asm/sym"

import (
	"fmt"
	"sort"
	"strings"
)

type opType int

const opAdd = opType(1)
const opMul = opType(2)
const opXor = opType(3)

type op struct {
	typ      opType
	operands operands
}

func newOp(typ opType, operands operands) U64 {
	res := op{typ: typ, operands: operands}
	sort.Sort(sortedOperands(res.operands))
	return res.Simplify()
}

func (o op) Simplify() U64 {
	switch o.typ {
	case opAdd:
		return o.SimplifyAdd()
	case opMul:
		return o.SimplifyMul()
	case opXor:
		return o.SimplifyXor()
	}
	return o
}

func (v op) Eval(other U64) bool {
	switch typed := other.(type) {
	case op:
		if v.typ != typed.typ || len(v.operands) != len(typed.operands) {
			return false
		}
		if len(v.operands) != 2 {
			return v.operands.Eval(typed.operands)
		}
		// todo how to do this more elegant?
		if v.operands[0].Eval(typed.operands[0]) && v.operands[1].Eval(typed.operands[1]) {
			return true
		}
		if v.operands[0].Eval(typed.operands[1]) && v.operands[1].Eval(typed.operands[0]) {
			return true
		}
		return false
	default:
		return false
	}
}

func (o op) String() string {
	ss := make([]string, len(o.operands))
	for i := range o.operands {
		ss[i] = o.operands[i].String()
	}
	sep := ""
	switch o.typ {
	case opAdd:
		sep = "+"
	case opMul:
		sep = "*"
	case opXor:
		sep = "^"
	}
	return fmt.Sprintf("( %s )", strings.Join(ss, sep))
}
