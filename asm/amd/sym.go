package amd

import (
	"fmt"
	"golang.org/x/arch/x86/x86asm"
	"sort"
	"strings"
)

type U64 interface {
	Simplify() U64
	Match(v U64) bool
	String() string
}

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

func (v immediate) Match(other U64) bool {
	switch typed := other.(type) {
	case immediate:
		return v.Value == typed.Value
	case ImmediateExtractor:
		*typed.Value = v.Value
		return true
	default:
		return false
	}
}

type ImmediateExtractor struct {
	Value *uint64
}

func (v ImmediateExtractor) Simplify() U64 {
	return v
}

func (v ImmediateExtractor) String() string {
	return fmt.Sprintf(" ??? ")
}

func (v ImmediateExtractor) Match(cmp U64) bool {
	return false
}

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

func (v mem) Match(other U64) bool {
	switch typed := other.(type) {
	case mem:
		if v.segment != typed.segment {
			return false
		}
		return v.at.Match(typed.at)
	default:
		return false
	}
}

type mul struct {
	vs sortedCollection
}

func (v mul) String() string {
	ss := make([]string, len(v.vs))
	for i := range v.vs {
		ss[i] = v.vs[i].String()
	}
	return fmt.Sprintf("( %s )", strings.Join(ss, " * "))
}

func Mul(vs ...U64) U64 {
	res := mul{vs: vs}
	sort.Sort(res.vs)
	return res.Simplify()
}

func (v mul) Simplify() U64 {
	for {
		var t1, t2 immediate
		if !peek2(v.vs, &t1, &t2) {
			break
		}
		v.vs.Pop()
		v.vs.Pop()
		v.vs.Push(Imm(t1.Value * t2.Value))
	}
	{
		var t1 immediate
		if peek1(v.vs, &t1) {
			if t1.Value == 1 {
				v.vs.Pop()
			}
			if t1.Value == 0 {
				return Imm(0)
			}
		}
	}
	{
		var a add
		var i immediate
		if len(v.vs) == 2 && peek2(v.vs, &a, &i) {
			var res []U64
			for _, ait := range a.vs {
				res = append(res, Mul(i, ait).Simplify())
			}
			return Add(res...)
		}
	}
	if len(v.vs) == 1 {
		return v.vs[0]
	}
	return v
}

func (v mul) Match(other U64) bool {
	switch typed := other.(type) {
	case mul:
		return match(v.vs, typed.vs)
	default:
		return false
	}
}

func Add(vs ...U64) U64 {
	res := add{vs: vs}
	sort.Sort(res.vs)

	return res.Simplify()
}

type add struct {
	vs sortedCollection
}

func (v add) String() string {
	ss := make([]string, len(v.vs))
	for i := range v.vs {
		ss[i] = v.vs[i].String()
	}
	return fmt.Sprintf("( %s )", strings.Join(ss, " + "))
}

func (v add) Simplify() U64 {
	for {
		var t1, t2 immediate
		if !peek2(v.vs, &t1, &t2) {
			break
		}
		v.vs.Pop()
		v.vs.Pop()
		v.vs.Push(Imm(t1.Value + t2.Value))
	}
	{
		var t1 immediate
		if peek1(v.vs, &t1) && t1.Value == 0 {
			v.vs.Pop()
		}
	}
	modified := false
	for {
		var adds []add
		var notAdds []U64
		for i := 0; i < v.vs.Len(); i++ {
			it := v.vs[i]
			if vv, ok := it.(add); ok {
				adds = append(adds, vv)
			} else {
				notAdds = append(notAdds, it)
			}
		}
		if len(adds) == 0 {
			break
		}
		for _, it := range adds {
			for _, it2 := range it.vs {
				notAdds = append(notAdds, it2)
			}
		}
		v.vs = notAdds
		modified = true
	}
	if len(v.vs) == 1 {
		return v.vs[0]
	}
	if len(v.vs) == 0 {
		return Imm(0)
	}
	if modified {
		sort.Sort(v.vs)
		return v.Simplify()
	}

	return v
}

func (v add) Match(other U64) bool {
	switch typed := other.(type) {
	case add:
		return match(v.vs, typed.vs)
	default:
		return false
	}
}

func match(v, typed sortedCollection) bool {
	if len(v) != len(typed) {
		return false
	}
	for i := 0; i < len(v); i++ {
		if !v[i].Match(typed[i]) {
			return false
		}
	}
	return true
}

type Sym struct {
	Name string
}

func (v Sym) Simplify() U64 {
	return v
}

func (v Sym) String() string {
	return fmt.Sprintf("{ @%s }", v.Name)
}

func (v Sym) Match(other U64) bool {
	switch typed := other.(type) {
	case Sym:
		return v.Name == typed.Name
	default:
		return false
	}
}

type sortedCollection []U64

func (s sortedCollection) Len() int {
	return len(s)
}

func (s sortedCollection) Less(i, j int) bool {
	return cmpOrder(s[i]) < cmpOrder(s[j])
}

func (s sortedCollection) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (s *sortedCollection) Pop() {
	*s = (*s)[:len(*s)-1]
}
func (s *sortedCollection) Push(v U64) {
	*s = append(*s, v)
}

func peek2[T1 U64, T2 U64](s sortedCollection, t1 *T1, t2 *T2) bool {
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

func peek1[T1 U64](s sortedCollection, t1 *T1) bool {
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
	case Sym:
		return 2
	case mul:
		return 4
	case add:
		return 5
	case immediate:
		return 6
	case ImmediateExtractor:
		return 7
	default:
		return 0
	}
}
