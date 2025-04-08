// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package sym // import "go.opentelemetry.io/ebpf-profiler/asm/sym"

func Xor(vs ...U64) U64 {
	return newOp(opXor, vs)
}

func (o op) SimplifyXor() U64 {
	for {
		var t1, t2 immediate
		if !peek2(o.operands, &t1, &t2) {
			break
		}
		o.operands.Pop()
		o.operands.Pop()
		o.operands.Push(Imm(t1.Value ^ t2.Value))
	}
	if len(o.operands) == 1 {
		return o.operands[0]
	}
	if len(o.operands) == 2 && o.operands[0].Eval(o.operands[1]) {
		return Imm(0)
	}
	return o
}
