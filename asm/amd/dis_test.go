package amd

import (
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"golang.org/x/arch/x86/x86asm"
)

type memory struct {
	code []byte
}

func (m *memory) VirtualMemory(addr int64, sz, maxSize int) ([]byte, error) {
	if int(addr) >= len(m.code) {
		return nil, io.EOF
	}
	res := m.code[int(addr):]
	if sz > maxSize {
		sz = maxSize
	}
	if sz > len(res) {
		return nil, errors.New("oob")
	}
	return res[:sz], nil
}

func TestDisassembler(t *testing.T) {
	code := []byte{
		//inc   rax;
		//call  0x10040;
		//mov   rax, qword ptr[rdx + 4];
		//sub   esp, 0x100;
		//xchg  rdi, rsi;
		//pop   rbx;
		0x48, 0xFF, 0xC0, 0xE8, 0x38, 0x00, 0x00, 0x00,
		0x48, 0x8B, 0x42, 0x04, 0x81, 0xEC, 0x00, 0x01,
		0x00, 0x00, 0x48, 0x87, 0xF7, 0x5B,
	}
	expected := []x86asm.Op{
		x86asm.INC,
		x86asm.CALL,
		x86asm.MOV,
		x86asm.SUB,
		x86asm.XCHG,
		x86asm.POP,
	}
	bufSizes := []int{}
	for i := 1; i < 128; i++ {
		bufSizes = append(bufSizes, i)
	}
	for _, bufSize := range bufSizes {
		d := NewDisassembler(&memory{code}, 0, libpf.Address(len(code)))
		d.bufSize = bufSize
		var actual []x86asm.Op
		for {
			inst, _, err := d.Next()
			if err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				require.NoError(t, err)
			}
			actual = append(actual, inst.Op)
		}
		require.Equal(t, expected, actual)
	}
}
