// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package variable // import "go.opentelemetry.io/ebpf-profiler/asm/variable"

func Xor(vs ...U64) U64 {
	v := uint64(0)
	ops := make(operands, 0, len(vs))
	for i := range vs {
		if imm, immOk := vs[i].(immediate); immOk {
			v ^= imm.Value
		} else {
			ops = append(ops, vs[i])
		}
	}
	if len(ops) == 0 {
		return Imm(v)
	}
	if v != 0 {
		ops = append(ops, Imm(v))
	}
	//todo learn why does this cmp panics
	//if len(ops) == 2 && (ops[0] == ops[1] || ops[0].Eval(ops[1])) {
	// todo do not use eval here
	if len(ops) == 2 && (ops[0].Eval(ops[1])) {
		return Imm(0)
	}
	if len(ops) == 1 {
		return ops[0]
	}
	return newOp(opXor, ops)
}
