package amd

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestAdd(t *testing.T) {
	testdata := []struct {
		name string
		a    U64
		b    U64
	}{
		{
			"add sort-summ-immediates",
			Add(Sym{}, Imm(14)),
			Add(Imm(1), Imm(3), Imm(1), Sym{}, Imm(9)),
		},
		{
			"add 0",
			Add(Sym{}),
			Add(Imm(0), Sym{}),
		},
		{
			"add nested",
			Add(Add(Sym{Name: "s1"}, Sym{"s3"}), Sym{Name: "s2"}),
			Add(Sym{Name: "s2"}, Sym{"s1"}, Sym{Name: "s3"}),
		},
		{
			"add rhug",
			Add(Add(Imm(2), Sym{Name: "s1"}), Imm(7)),
			Add(Sym{Name: "s1"}, Imm(9)),
		},
		{
			"add 1 element",
			Add(Imm(2)),
			Imm(2),
		},
		{
			"mul immediates",
			Mul(Sym{}, Imm(27)),
			Mul(Imm(1), Imm(3), Imm(1), Sym{}, Imm(9)),
		},
		{
			"mul 1",
			Mul(Sym{}),
			Mul(Imm(1), Sym{}),
		}, {
			"mul 0",
			Imm(0),
			Mul(Imm(0), Imm(3), Imm(1), Sym{}, Imm(9)),
		},
	}

	for _, td := range testdata {
		t.Run(td.name, func(t *testing.T) {
			assert.Equal(t, td.a, td.b)
		})

	}

}
