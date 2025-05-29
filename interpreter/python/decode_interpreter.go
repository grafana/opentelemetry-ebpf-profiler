package python

import (
	"cmp"
	"encoding/binary"
	"errors"
	"io"
	"slices"

	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/ebpf-profiler/asm/amd"
	"go.opentelemetry.io/ebpf-profiler/asm/dfs"
	"go.opentelemetry.io/ebpf-profiler/asm/variable"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/util"
	"golang.org/x/arch/x86/x86asm"
)

// investigate 1a2eb220c22ae7ba8aaf8b243e57dbc25542f8c9c269ed6100c7ad5aea7c3ada 1 extra ranges - prune ud?
// fix coredump tests
// PeekUnexplored and reassignIndexes are too hot in benchmarks
// add alpine and debian docker, ubuntu tests
// fuzz for timeouts
// todo accept Symbol and makesure it is included and merged in the res
// todo if the result has more than 2 ranges - return the start and the biggest non intersected one
func decodeInterpreterRanges(ef *pfelf.File, start util.Range) ([]util.Range, error) {
	var err error
	d := new(dfs.DFS)
	d.AddBasicBlock(start.Start)
	r := rangesRecoverer{
		ef:                      ef,
		d:                       d,
		indirectJumpDestination: make([]uint64, 0, 256),
		opcodeTableAddress:      0,
	}
	recovered := 0
	for i := 0; i < 3; i++ {
		indirectJumpsFrom := map[uint64]struct{}{}
		if err = amd.Explore(ef, d, indirectJumpsFrom); err != nil {
			return nil, err
		}

		if recovered, err = r.recoverIndirectJumps(indirectJumpsFrom); err != nil {
			return nil, err
		}
		if recovered == 0 {
			break
		}
	}

	recoveredRanges := d.Ranges()
	return mergeRecoveredRanges(start, recoveredRanges), nil
}

func (r *rangesRecoverer) recoverIndirectJumps(indirectJumpsSource map[uint64]struct{}) (int, error) {
	recovered := 0
	for srcAddr, _ := range indirectJumpsSource {
		src := r.d.FindBasicBlock(srcAddr)
		if src == nil {
			logrus.Errorf("programming error: failed to find block at %x", srcAddr)
			continue // should not happen
		}
		err := r.collectIndirectJumpDestinations(src)
		if err != nil {
			return recovered, err
		}
		for _, dst := range r.indirectJumpDestination {
			b := r.d.AddBasicBlock(dst)
			r.d.AddEdge(src, b, dfs.EdgeTypeJump)
			recovered++
		}

	}
	return recovered, nil
}

func getBlocksWithCode(ef *pfelf.File, blocks []*dfs.BasicBlock) ([]amd.BasicBlockCode, error) {
	var err error
	blocksWithCode := make([]amd.BasicBlockCode, len(blocks))
	for i := range blocks {
		var b *dfs.BasicBlock = blocks[i]
		blockWithCode := amd.BasicBlockCode{
			Address: variable.Imm(b.Start()),
			Code:    make([]byte, b.Size()),
		}
		_, err2 := ef.ReadAt(blockWithCode.Code, int64(b.Start()))
		blocksWithCode[i], err = blockWithCode, err2
		if err != nil {
			return nil, err
		}
	}
	return blocksWithCode, nil
}

func (r *rangesRecoverer) collectIndirectJumpDestinations(bb *dfs.BasicBlock) error {

	//defer func() {
	//	fmt.Printf("indirect jump at bb %x => %d jumps\n", bb.Start(), len(r.indirectJumpDestination))
	//}()
	var err error
	blocks := r.d.FallThroughBlocksTo(bb, 3)
	blocksWithCode, err := getBlocksWithCode(r.ef, blocks)
	if err != nil {
		return err
	}

	r.indirectJumpDestination = r.indirectJumpDestination[:0]
	interp := amd.NewInterpreter().WithMemory()
	lastInsn, err := interp.LoopBlocks(blocksWithCode)
	if !errors.Is(err, io.EOF) {
		return err
	}
	if lastInsn.Op != x86asm.JMP {
		return nil
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
		if r.opcodeTableAddress == 0 {
			if actual.Eval(variable.Mem(jmp256Pattern, 8)) {
				return r.recoverOpcodeJumpTable(jmp256Table.ExtractedValue)
			}
		}
		if actual.Eval(jmp4Pattern) {
			return r.recoverSwitchCase4(jmp4Base.ExtractedValue, jmp4Table.ExtractedValue)
		}
		return nil
	case x86asm.Mem:
		if r.opcodeTableAddress == 0 {
			actual := interp.MemArg(typed)
			if actual.Eval(jmp256Pattern) {
				return r.recoverOpcodeJumpTable(jmp256Table.ExtractedValue)
			}
		}
	}
	return nil
}

func (r *rangesRecoverer) recoverOpcodeJumpTable(table uint64) error {
	if r.opcodeTableAddress != 0 {
		return nil
	}
	switchTableValues := make([]byte, 8*256)
	if _, err := r.ef.ReadAt(switchTableValues, int64(table)); err != nil {
		return err
	}
	for i := 0; i < 256; i++ {
		it := switchTableValues[i*8 : i*8+8]
		jmp := binary.LittleEndian.Uint64(it)
		r.indirectJumpDestination = append(r.indirectJumpDestination, jmp)
	}
	r.opcodeTableAddress = table
	return nil
}

func (r *rangesRecoverer) recoverSwitchCase4(base, table uint64) error {
	switchTableValues := make([]byte, 4*4)
	if _, err := r.ef.ReadAt(switchTableValues, int64(table)); err != nil {
		return err
	}
	for i := 0; i < 4; i++ {
		it := switchTableValues[i*4 : i*4+4]
		jmp := int32(binary.LittleEndian.Uint32(it))
		dst := uint64(int64(base) + int64(jmp))
		r.indirectJumpDestination = append(r.indirectJumpDestination, dst)
	}
	return nil
}

type rangesRecoverer struct {
	ef                      *pfelf.File
	d                       *dfs.DFS
	indirectJumpDestination []uint64
	opcodeTableAddress      uint64
}

func mergeRecoveredRanges(start util.Range, recovered []util.Range) []util.Range {
	it := start
	res := make([]util.Range, 0, len(recovered))
	for _, v := range recovered {
		if (v.Start >= it.Start && v.Start < it.End) || (v.End >= it.Start && v.End < it.End) {
			it.Start = min(it.Start, v.Start)
			it.End = max(it.End, v.End)
		} else {
			res = append(res, v)
		}
	}
	res = append(res, it)
	slices.SortFunc(res, func(a, b util.Range) int {
		return cmp.Compare(a.Start, b.Start)
	})
	return res
}
