// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package sym // import "go.opentelemetry.io/ebpf-profiler/asm/sym"

type U64 interface {
	Simplify() U64
	Eval(v U64) bool
	String() string
}

type operands []U64

type sortedOperands operands

func (s sortedOperands) Len() int {
	return len(s)
}

func (s sortedOperands) Less(i, j int) bool {
	return cmpOrder(s[i]) < cmpOrder(s[j])
}

func (s sortedOperands) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (s *operands) Pop() {
	*s = (*s)[:len(*s)-1]
}
func (s *operands) Push(v U64) {
	*s = append(*s, v)
}

func peek2[T1 U64, T2 U64](s operands, t1 *T1, t2 *T2) bool {
	if len(s) < 2 {
		return false
	}
	tt2, ok2 := s[len(s)-1].(T2)
	tt1, ok1 := s[len(s)-2].(T1)
	if !ok2 {
		return false
	}
	if !ok1 {
		return false
	}
	*t2 = tt2
	*t1 = tt1
	return true

}

func peek1[T1 U64](s operands, t1 *T1) bool {
	if len(s) < 1 {
		return false
	}
	tt1, ok1 := s[len(s)-1].(T1)
	if !ok1 {
		return false
	}
	*t1 = tt1
	return true

}

func cmpOrder(u U64) int {
	switch u.(type) {
	case mem:
		return 1
	case op:
		return 2
	case immediate:
		return 3
	case *Variable:
		return 3
	default:
		return 0
	}
}

func (v operands) Eval(typed operands) bool {
	if len(v) != len(typed) {
		return false
	}
	for i := 0; i < len(v); i++ {
		if !v[i].Eval(typed[i]) {
			return false
		}
	}
	return true
}
