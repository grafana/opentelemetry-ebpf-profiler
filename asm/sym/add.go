// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package sym // import "go.opentelemetry.io/ebpf-profiler/asm/sym"

func Add(vs ...U64) U64 {
	var addOperands = []U64{}
	for i := 0; i < len(vs); i++ {
		if op, ok := vs[i].(op); ok && op.typ == opAdd {
			addOperands = append(addOperands, op.operands...)
			vs[i] = nil
		}
	}
	if len(addOperands) == 0 {
		return newOp(opAdd, vs)
	}
	for _, v := range vs {
		if v != nil {
			addOperands = append(addOperands, v)
		}
	}

	return newOp(opAdd, addOperands)

}

func (o op) SimplifyAdd() U64 {
	for {
		var t1, t2 immediate
		if !peek2(o.operands, &t1, &t2) {
			break
		}
		o.operands.Pop()
		o.operands.Pop()
		o.operands.Push(Imm(t1.Value + t2.Value))
	}
	{
		var t1 immediate
		if peek1(o.operands, &t1) && t1.Value == 0 {
			o.operands.Pop()
		}
	}
	//modified := false
	//for {
	//	var adds []op
	//	var notAdds []U64
	//	for i := 0; i < len(o.operands); i++ {
	//		it := o.operands[i]
	//		if vv, ok := it.(op); ok && vv.typ == opAdd {
	//			adds = append(adds, vv)
	//		} else {
	//			notAdds = append(notAdds, it)
	//		}
	//	}
	//	if len(adds) == 0 {
	//		break
	//	}
	//	for _, it := range adds {
	//		for _, it2 := range it.operands {
	//			notAdds = append(notAdds, it2)
	//		}
	//	}
	//	o.operands = notAdds
	//	modified = true
	//}
	if len(o.operands) == 1 {
		return o.operands[0]
	}
	if len(o.operands) == 0 {
		return Imm(0)
	}
	//if modified {
	//	sort.Sort(sortedOperands(o.operands))
	//	return o.Simplify()
	//}
	return o
}
