package python

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"go.opentelemetry.io/ebpf-profiler/asm/amd"
	"go.opentelemetry.io/ebpf-profiler/asm/dfs"
	"go.opentelemetry.io/ebpf-profiler/asm/variable"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/util"
	"golang.org/x/arch/x86/x86asm"
)

// fix coredump tests
// PeekUnexplored and reassignIndexes are too hot
// add alpine and debian docker, ubuntu tests
// fuzz for timeouts
// todo accept Symbol and makesure it is included and merged in the res
func decodeInterpreterRanges(ef *pfelf.File, start uint64) ([]util.Range, error) {
	var err error
	d := new(dfs.DFS)
	d.AddBasicBlock(start)
	for i := 0; i < 2; i++ {
		indirectJumps := map[uint64]struct{}{}
		if err = amd.Explore(ef, d, indirectJumps); err != nil {
			return nil, err
		}

		if err = recoverIndirectJumps(ef, indirectJumps, d); err != nil {
			return nil, err
		}
	}

	if err = amd.Explore(ef, d, nil); err != nil {
		return nil, err
	}
	return d.Ranges(), nil
}
func getBlockCode(b *dfs.BasicBlock, ef *pfelf.File) (amd.Block, error) {
	blockWithCode := amd.Block{
		Address: variable.Imm(b.Start()),
		Code:    make([]byte, b.Size()),
	}
	_, err := ef.ReadAt(blockWithCode.Code, int64(b.Start()))
	return blockWithCode, err
}

func recoverIndirectJumps(ef *pfelf.File, indirectJumps map[uint64]struct{}, d *dfs.DFS) error {
	for addr, _ := range indirectJumps {
		block := d.FindBasicBlock(addr)
		if block == nil {
			return fmt.Errorf("found reg jump, but not corresponding basic block")
		}
		blockWithCode, err := getBlockCode(block, ef)
		if err != nil {
			return err
		}
		recovered, err := recoverIndirectJumpsFromBlocks(ef, d, block, []amd.Block{blockWithCode})
		if err != nil {
			return err
		}
		if recovered {
			continue
		}
		edges := d.EdgesTo(block)
		for _, e := range edges {
			prevBlock, err := getBlockCode(e, ef)
			if err != nil {
				return err
			}
			blocks := []amd.Block{prevBlock, blockWithCode}
			recovered, err = recoverIndirectJumpsFromBlocks(ef, d, block, blocks)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func recoverIndirectJumpsFromBlocks(ef *pfelf.File, d *dfs.DFS, termBB *dfs.BasicBlock, blocks []amd.Block) (bool, error) {
	interp := amd.NewInterpreter()
	lastInsn, err := interp.LoopBlocks(blocks)
	if !errors.Is(err, io.EOF) {
		return false, err
	}
	if lastInsn.Op != x86asm.JMP {
		return false, nil
	}
	jmp256Table := variable.Var("jmp256Table")
	jmp256Pattern := variable.Add(
		variable.Mul(
			variable.ZeroExtend(variable.Mem(variable.Any(), 8), 8),
			variable.Imm(8),
		),
		jmp256Table,
	)
	jmp4Table := variable.Var("jmp4Table")
	jmp4Base := variable.Var("jmp4Base")
	jmp4Pattern := variable.Add(
		variable.SignExtend(
			variable.Mem(
				variable.Add(
					variable.Mul(
						variable.ZeroExtend(variable.Any(), 2),
						variable.Imm(4),
					),
					jmp4Table,
				),
				4,
			),
			64,
		),
		jmp4Base,
	)

	switch typed := lastInsn.Args[0].(type) {
	case x86asm.Reg:
		actual := interp.Regs.Get(typed)
		if actual.Eval(variable.Mem(jmp256Pattern, 8)) {
			if err = recover256(ef, d, termBB, jmp256Table.ExtractedValue); err != nil {
				return false, err
			}
			return true, nil
		}

		if actual.Eval(jmp4Pattern) {
			if err = recover4(ef, d, termBB, jmp4Base.ExtractedValue, jmp4Table.ExtractedValue); err != nil {
				return false, err
			}
			return true, nil
		}
		return false, nil
	case x86asm.Mem:
		actual := interp.MemArg(typed)
		if actual.Eval(jmp256Pattern) {
			if err = recover256(ef, d, termBB, jmp256Table.ExtractedValue); err != nil {
				return false, err
			}
			return true, nil
		}

	}
	return false, nil
}

func recover256(ef *pfelf.File, d *dfs.DFS, termBB *dfs.BasicBlock, at uint64) error {
	switchTableValues := make([]byte, 8*256)
	if _, err := ef.ReadAt(switchTableValues, int64(at)); err != nil {
		return err
	}
	for i := 0; i < 256; i++ {
		it := switchTableValues[i*8 : i*8+8]
		jmp := binary.LittleEndian.Uint64(it)
		b := d.AddBasicBlock(jmp)
		d.AddEdge(termBB, b, dfs.EdgeTypeJump)
	}
	return nil
}

func recover4(ef *pfelf.File, d *dfs.DFS, termBB *dfs.BasicBlock, base, table uint64) error {
	switchTableValues := make([]byte, 4*4)
	if _, err := ef.ReadAt(switchTableValues, int64(table)); err != nil {
		return err
	}
	for i := 0; i < 4; i++ {
		it := switchTableValues[i*4 : i*4+4]
		jmp := int32(binary.LittleEndian.Uint32(it))
		dst := uint64(int64(base) + int64(jmp))
		b := d.AddBasicBlock(dst)
		d.AddEdge(termBB, b, dfs.EdgeTypeJump)
	}
	return nil
}
