// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package sym // import "go.opentelemetry.io/ebpf-profiler/asm/sym"

func Mul(vs ...U64) U64 {
	return newOp(opMul, vs)
}

func (o op) SimplifyMul() U64 {
	for {
		var t1, t2 immediate
		if !peek2(o.operands, &t1, &t2) {
			break
		}
		o.operands.Pop()
		o.operands.Pop()
		o.operands.Push(Imm(t1.Value * t2.Value))
	}
	{
		var t1 immediate
		if peek1(o.operands, &t1) {
			if t1.Value == 1 {
				o.operands.Pop()
			}
			if t1.Value == 0 {
				return Imm(0)
			}
		}
	}
	{
		var a op
		var i immediate
		if len(o.operands) == 2 && peek2(o.operands, &a, &i) && a.typ == opAdd {
			var res []U64
			for _, ait := range a.operands {
				res = append(res, Mul(i, ait).Simplify())
			}
			return Add(res...)
		}
	}
	if len(o.operands) == 1 {
		return o.operands[0]
	}
	return o
}
