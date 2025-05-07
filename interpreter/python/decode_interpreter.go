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

// backport to upstream pr: last insn return in interp, any in var sym

// unhandled jump: ff24ea41c7452801000000488b050ab9 JMP [RDX+8*RBP] \n"
// fix coredump tests
//
//	cache decoding results somewhere
//
// PeekUnexplored and reassignIndexes are too hot
// add alpine and debian docker tests
// check if the last instruction is jmp rax
// find some more pythons that have non consecutive blocks joined by ud or int3, add tests for merging these
// fuzz for timeouts
// todo accept Symbol and makesure it is included and merged in the res
func decodeInterpreterRanges(ef *pfelf.File, start uint64) ([]util.Range, error) {
	var err error
	d := new(dfs.DFS)
	d.AddBasicBlock(start)
	for i := 0; i < 2; i++ {
		fmt.Printf("====================\n")
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
		fmt.Printf("==========================\nindirect jump at %x in block %s\n", addr, block)
		blockWithCode, err := getBlockCode(block, ef)
		if err != nil {
			return err
		}
		recovered, err := recoverIndirectJumpsFromBlocks(ef, d, block, []amd.Block{blockWithCode})
		if err != nil {
			return err
		}
		fmt.Printf("recovered %v\n", recovered)
		if recovered {
			continue
		}
		edges := d.EdgesTo(block)
		fmt.Printf("   >> found %s edges\n", edges)
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
	for i, block := range blocks {
		fmt.Printf("recovering %d %s\n", i, block.Address)
	}
	interp := amd.NewInterpreter()
	lastInsn, err := interp.LoopBlocks(blocks)
	if !errors.Is(err, io.EOF) {
		return false, err
	}
	fmt.Println("    " + lastInsn.String())
	//fmt.Println(interp.Regs.DebugString())
	if lastInsn.Op != x86asm.JMP {
		return false, nil
	}
	switchTable := variable.Var("switch table")

	switch typed := lastInsn.Args[0].(type) {
	case x86asm.Reg:
		actual := interp.Regs.Get(typed)
		expected := variable.Mem(variable.Add(
			variable.Mul(
				variable.ZeroExtend(variable.Mem(variable.Any()), 8),
				variable.Imm(8),
			),
			switchTable,
		))
		if actual.Eval(expected) {
			fmt.Printf("   evaled\n")
			if err = recover256(ef, d, termBB, switchTable.ExtractedValue); err != nil {
				return false, err
			}
			fmt.Printf("        !recovered\n")
			return true, nil
		}

		//expected := variable.Mem(variable.Add(
		//	variable.Mul(
		//		variable.ZeroExtend(variable.Any()), 2),
		//		variable.Imm(8),
		//	),
		//	switchTable,
		//))
		//
		fmt.Printf("expected %s\n", expected.String())
		fmt.Printf("actual   %s\n", actual.String())
		return false, nil
	case x86asm.Mem:
		actual := interp.MemArg(typed)
		expected := variable.Add(
			variable.Mul(
				variable.ZeroExtend(variable.Mem(variable.Any()), 8),
				variable.Imm(8),
			),
			switchTable,
		)
		if actual.Eval(expected) {
			fmt.Printf("   evaled\n")

			if err = recover256(ef, d, termBB, switchTable.ExtractedValue); err != nil {
				return false, err
			}
			fmt.Printf("        !recovered\n")
			return true, nil
		}

	}
	return false, nil
}

func recover256(ef *pfelf.File, d *dfs.DFS, termBB *dfs.BasicBlock, at uint64) error {
	fmt.Printf("                   switch table 256 %x\n", at)

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
