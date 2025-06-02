package amd

import (
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/asm/variable"
	"golang.org/x/arch/x86/x86asm"
)

func BenchmarkPythonInterpreter(b *testing.B) {
	for i := 0; i < b.N; i++ {
		testPythonInterpreter(b)
	}
}

func TestPythonInterpreter(t *testing.T) {
	testPythonInterpreter(t)
}

func testPythonInterpreter(t testing.TB) {
	// 00010000 	4D 89 F2 	mov 	r10, r14
	// 00010003 	45 0F B6 36 	movzx 	r14d, byte ptr [r14]
	// 00010007 	48 8D 05 2D B3 35 00 	lea 	rax, [rip + 0x35b32d]
	// 0001000E 	4C 8B 6C 24 08 	mov 	r13, qword ptr [rsp + 8]
	// 00010013 	48 89 C1 	mov 	rcx, rax
	// 00010016 	48 89 44 24 10 	mov 	qword ptr [rsp + 0x10], rax
	// 0001001B 	45 0F B6 5A 01 	movzx 	r11d, byte ptr [r10 + 1]
	// 00010020 	41 0F B6 C6 	movzx 	eax, r14b
	// 00010024 	48 8B 04 C1 	mov 	rax, qword ptr [rcx + rax*8]
	// 00010028 	FF E0 	jmp 	rax
	code := []byte{
		0x4d, 0x89, 0xf2, 0x45, 0x0f, 0xb6, 0x36, 0x48, 0x8d, 0x05, 0x2d, 0xb3, 0x35,
		0x00, 0x4c, 0x8b, 0x6c, 0x24, 0x08, 0x48, 0x89, 0xc1, 0x48, 0x89, 0x44, 0x24,
		0x10, 0x45, 0x0f, 0xb6, 0x5a, 0x01, 0x41, 0x0f, 0xb6, 0xc6, 0x48, 0x8b, 0x04,
		0xc1, 0xff, 0xe0,
	}
	it := NewInterpreterWithCode(code)
	it.CodeAddress = variable.Imm(0x8AF05)

	_, err := it.Loop()
	if err == nil || err != io.EOF {
		t.Fatal(err)
	}
	actual := it.Regs.Get(x86asm.RAX)
	expected := variable.Mem(
		variable.Add(
			variable.Mul(
				variable.ZeroExtend(variable.Mem(variable.Any(), 8), 8),
				variable.Imm(8),
			),
			variable.Var("switch table"),
		),
		8,
	)
	if !actual.Eval(expected) {
		t.Fatal()
	}
}

func TestRecoverSwitchCase(t *testing.T) {
	blocks := []CodeBlock{
		{
			Address: variable.Imm(0x3310E3),
			Code:    []byte{0x48, 0x8b, 0x44, 0x24, 0x20, 0x48, 0x89, 0x18, 0x49, 0x83, 0xc2, 0x02, 0x44, 0x89, 0xe0, 0x83, 0xe0, 0x03, 0x31, 0xdb, 0x41, 0xf6, 0xc4, 0x04, 0x4c, 0x89, 0x74, 0x24, 0x10, 0x74, 0x08},
		},
		{
			Address: variable.Imm(0x33110a),
			Code: []byte{
				0x4d, 0x89, 0xdc, 0x4d, 0x8d, 0x47, 0xf8, 0x4c, 0x89, 0x7c, 0x24, 0x60, 0x4d, 0x8b, 0x7f, 0xf8, 0x48, 0x8b, 0x0d, 0x87, 0x06, 0x17, 0x01, 0x89, 0xc0, 0x48, 0x8d, 0x15, 0x02, 0xe7, 0xc0, 0x00, 0x48, 0x63, 0x04, 0x82, 0x48, 0x01, 0xd0, 0x4c, 0x89, 0xd5, 0x4d, 0x89, 0xc5, 0xff, 0xe0,
			},
		},
	}
	t.Run("manual", func(t *testing.T) {
		it := NewInterpreter()
		initR12 := it.Regs.Get(x86asm.R12)
		it.ResetCode(blocks[0].Code, blocks[0].Address)
		_, err := it.Loop()
		require.ErrorIs(t, err, io.EOF)

		expected := variable.ZeroExtend(initR12, 2)
		assertEval(t, it.Regs.Get(x86asm.RAX), expected)
		it.ResetCode(blocks[1].Code, blocks[1].Address)
		_, err = it.Loop()
		require.ErrorIs(t, err, io.EOF)
		table := variable.Var("table")
		base := variable.Var("base")
		expected = variable.Add(
			variable.SignExtend(
				variable.Mem(
					variable.Add(
						variable.Mul(
							variable.ZeroExtend(initR12, 2),
							variable.Imm(4),
						),
						table,
					),
					4,
				),
				64,
			),
			base,
		)
		assertEval(t, it.Regs.Get(x86asm.RAX), expected)
		assert.EqualValues(t, 0xf3f82c, table.ExtractedValue)
		assert.EqualValues(t, 0xf3f82c, base.ExtractedValue)
	})
}

func assertEval(t *testing.T, left, right variable.U64) {
	if !left.Eval(right) {
		assert.Fail(t, "failed to eval %s to %s", left.String(), right.String())
		t.Logf("left  %s", left.String())
		t.Logf("right %s", right.String())
	}
}

func TestSLow(t *testing.T) {
	it := NewInterpreterWithCode([]byte("0\xf20\xd1\x01\xd1\x03\xd1\x01\xd13\xd1\x01\xd1\x01\xd1\x03\xd1\x01\xd12\xd10\xd12\xd10\xd10\xd10\xd10\xca\x03\xd10\xd1\x03\xd1\x01\xd1\x01\xd1\x03\x01\x00\xd12\xd10\xd12\xd10\xd1\x01\xd12\xd10\xd12\xd10\xd10\xd10\xd10\xca\x03\xd10\xd1\x03\xd1\x01\xd1\x01\xd1\x03\x01\x00\xd10\xd1\xd1\x010\xca0\xd10\xd10"))
	_, _ = it.Loop()
}

func FuzzInterpreter(f *testing.F) {
	f.Fuzz(func(_ *testing.T, code []byte) {
		i := NewInterpreterWithCode(code)
		_, _ = i.Loop()
	})
}

func TestMoveSignExtend(t *testing.T) {
	i := NewInterpreterWithCode([]byte{
		0xB8, 0x01, 0x00, 0x00, 0x00, 0x8B, 0x40, 0x04,
		0xB8, 0x02, 0x00, 0x00, 0x00, 0x48, 0x0F, 0xB6,
		0x40, 0x04, 0xB8, 0x03, 0x00, 0x00, 0x00, 0x48,
		0x0F, 0xBF, 0x40, 0x04,
	})
	i.Loop()
	//todo assert
}

func TestCompareJumpConstraints(t *testing.T) {
	i := NewInterpreterWithCode([]byte{
		0x41, 0x0f, 0xb7, 0x04, 0x24, 0x49, 0x83, 0xc4, 0x02, 0x0f, 0xb6, 0xf4, 0x44,
		0x0f, 0xb6, 0xf8, 0x41, 0x89, 0xf1, 0x41, 0x81, 0xff, 0xa5, 0x00, 0x00, 0x00,
		0x0f, 0x87, 0xbb, 0xab, 0xf1, 0xff, 0x45, 0x89, 0xf8, 0x42, 0xff, 0x24, 0xc5,
		0x40, 0xec, 0x6d, 0x00,
	})
	_, err := i.Loop()
	require.ErrorIs(t, err, io.EOF)
	r8 := i.Regs.Get(x86asm.R8L)
	fmt.Println(r8.String())
	maxValue := i.MaxValue(r8)
	require.EqualValues(t, maxValue, 0xa5)
}

func TestDebugPrinting(t *testing.T) {
	assert.False(t, DebugPrinting)
}
