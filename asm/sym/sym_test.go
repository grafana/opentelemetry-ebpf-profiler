package sym

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestAdd(t *testing.T) {
	v := &Variable{}
	s1 := &Variable{Name: "s1"}
	s2 := &Variable{Name: "s2"}
	s3 := &Variable{Name: "s3"}
	eax := &Variable{"eax", 0}
	testdata := []struct {
		name string
		a    U64
		b    U64
	}{
		{
			"add sort-summ-immediate",
			Add(v, Imm(14)),
			Add(Imm(1), Imm(3), Imm(1), v, Imm(9)),
		},
		{
			"add 0",
			Add(v),
			Add(Imm(0), v),
		},
		{
			"add nested",
			Add(Add(s1, s3), s2),
			Add(s1, s3, s2),
		},
		{
			"add opt",
			Add(Add(Imm(2), s1), Imm(7)),
			Add(s1, Imm(9)),
		},
		{
			"add 1 element",
			Add(Imm(2)),
			Imm(2),
		},
		{
			"mul immediate",
			Mul(v, Imm(27)),
			Mul(Imm(1), Imm(3), Imm(1), v, Imm(9)),
		},
		{
			"mul 1",
			Mul(v),
			Mul(Imm(1), v),
		},
		{
			"mul order",
			op{opMul, operands([]U64{v, Imm(239)})},
			Mul(Imm(239), v),
		},
		{
			"mul 0",
			Imm(0),
			Mul(Imm(0), Imm(3), Imm(1), v, Imm(9)),
		},
		{
			"xor 0",
			Imm(3),
			Xor(Imm(1), Imm(2)),
		},

		{
			"xor eax, eax",
			Imm(0),
			Xor(eax, eax),
		},
	}

	for _, td := range testdata {
		t.Run(td.name, func(t *testing.T) {
			assert.Equal(t, td.a, td.b)
		})

	}

}
