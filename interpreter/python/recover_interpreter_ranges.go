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

// PeekUnexplored and reassignIndexes are too hot in benchmarks
// fuzz for timeouts
// todo mark __Py_FatalErrorFunc as noreturn and mark the bb as explored
func recoverInterpreterRanges(ef *pfelf.File, start util.Range, pythonVersion uint16) ([]util.Range, error) {
	var err error
	d := new(dfs.DFS)
	d.AddBasicBlock(start.Start)
	r := rangesRecoverer{
		pythonVersion:           pythonVersion,
		ef:                      ef,
		d:                       d,
		indirectJumpDestination: make([]uint64, 0, 256),
		recoveredTables:         make(map[uint64]struct{}),
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
	recoveredRanges = mergeRecoveredRanges(start, recoveredRanges)
	//recoveredRanges = slices.DeleteFunc(recoveredRanges, func(e util.Range) bool {
	//	return (e.End - e.Start) <= 4
	//})
	return recoveredRanges, nil
}

func (r *rangesRecoverer) recoverIndirectJumps(indirectJumpsSource map[uint64]struct{}) (int, error) {
	recovered := 0
	indirectJumpsSourceOrdered := make([]uint64, 0, len(indirectJumpsSource))
	for j := range indirectJumpsSource {
		indirectJumpsSourceOrdered = append(indirectJumpsSourceOrdered, j)
	}
	slices.Sort(indirectJumpsSourceOrdered)
	//slices.Reverse(indirectJumpsSourceOrdered)
	for _, srcAddr := range indirectJumpsSourceOrdered {
		src := r.d.FindBasicBlock(srcAddr)
		if src == nil {
			logrus.Errorf("programming error: failed to find block at %x", srcAddr)
			continue // should not happen
		}
		err := r.collectIndirectJumpDestinations(src)
		if err != nil {
			return recovered, err
		}
		for k, dst := range r.indirectJumpDestination {
			if dst == 0 {
				continue
			}

			b := r.d.AddBasicBlock(dst)
			r.d.AddEdge(src, b, dfs.EdgeTypeJump)
			if r.pythonVersion >= pythonVer(3, 11) && len(r.indirectJumpDestination) >= 128 {
				if k == 0 { // CACHE
					//todo check that it is nop?
					//todo what if it is not nop?
					// what if it calls to noreturn func?
					if r.pythonVersion >= pythonVer(3, 13) {
						// Py_UNREACHABLE();
						b.MarkCallNoReturn()
					} else {
						// Py_FatalError("Executing a cache.");
						b.MarkExplored()
					}
				}
			}
			recovered++
		}

	}
	return recovered, nil
}

func getBlocksWithCode(ef *pfelf.File, blocks []*dfs.BasicBlock) (amd.CodeBlock, error) {
	if len(blocks) == 0 {
		return amd.CodeBlock{}, errors.New("no blocks")
	}
	var err error
	l := 0
	for _, block := range blocks {
		l += int(block.Size())
	}
	at := blocks[0].Start()
	res := amd.CodeBlock{Code: make([]byte, l), Address: variable.Imm(at)}
	_, err = ef.ReadAt(res.Code, int64(at))
	return res, err
}

func (r *rangesRecoverer) collectIndirectJumpDestinations(bb *dfs.BasicBlock) error {
	//defer func() {
	//	fmt.Printf("indirect jump at bb %x => %d \n", bb.Start(), len(r.indirectJumpDestination))
	//}()
	var err error
	blocks := r.d.FallThroughBlocksTo(bb, 3)
	code, err := getBlocksWithCode(r.ef, blocks)
	if err != nil {
		return err
	}

	r.indirectJumpDestination = r.indirectJumpDestination[:0]
	interp := amd.NewInterpreter().WithMemory()
	interp.ResetCode(code.Code, code.Address)
	lastInsn, err := interp.Loop()
	if !errors.Is(err, io.EOF) {
		return err
	}
	if lastInsn.Op != x86asm.JMP {
		return nil
	}
	jmp256Table := variable.Var("jmp256Table")
	mul := variable.Any()
	jmp256Pattern := variable.Add(
		variable.Multiply(
			mul,
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
					variable.Multiply(
						mul,
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
		//fmt.Println(actual.String())
		if actual.Eval(variable.Mem(jmp256Pattern, 8)) { // todo we need to have
			mv := interp.MaxValue(mul)
			if mv <= 255 {
				return r.recoverJumpTable1(jmp256Table.ExtractedValueImm(), mv+1)
			}
		}
		if actual.Eval(jmp4Pattern) {
			mv := interp.MaxValue(mul)
			if mv <= 255 {
				return r.recoverSwitchCase4(jmp4Base.ExtractedValueImm(), jmp4Table.ExtractedValueImm(), mv+1)
			}
		}
		return nil
	case x86asm.Mem:
		actual := interp.MemArg(variable.Options{NoUnwrap: true}, typed)
		if actual.Eval(jmp256Pattern) {
			mv := interp.MaxValue(mul)
			if mv <= 255 {
				return r.recoverJumpTable1(jmp256Table.ExtractedValueImm(), mv+1)
			}
		}
	}
	return nil
}

func (r *rangesRecoverer) recoverJumpTable1(table uint64, tableSize uint64) error {
	if _, ok := r.recoveredTables[table]; ok {
		return nil
	}
	switchTableValues := make([]byte, 8*tableSize)
	if _, err := r.ef.ReadAt(switchTableValues, int64(table)); err != nil {
		return err
	}
	for i := 0; i < int(tableSize); i++ {
		it := switchTableValues[i*8 : i*8+8]
		jmp := binary.LittleEndian.Uint64(it)
		r.indirectJumpDestination = append(r.indirectJumpDestination, jmp)
	}
	r.recoveredTables[table] = struct{}{}
	return nil
}

func (r *rangesRecoverer) recoverSwitchCase4(base, table, tableSize uint64) error {
	if _, ok := r.recoveredTables[table]; ok {
		return nil
	}
	switchTableValues := make([]byte, 4*int(tableSize))
	if _, err := r.ef.ReadAt(switchTableValues, int64(table)); err != nil {
		return err
	}
	for i := 0; i < int(tableSize); i++ {
		it := switchTableValues[i*4 : i*4+4]
		jmp := int32(binary.LittleEndian.Uint32(it))
		dst := uint64(int64(base) + int64(jmp))
		r.indirectJumpDestination = append(r.indirectJumpDestination, dst)
	}
	r.recoveredTables[table] = struct{}{}
	return nil
}

type rangesRecoverer struct {
	ef                      *pfelf.File
	d                       *dfs.DFS
	indirectJumpDestination []uint64
	recoveredTables         map[uint64]struct{}
	pythonVersion           uint16
}

func mergeRecoveredRanges(start util.Range, recovered []util.Range) []util.Range {
	it := start
	res := make([]util.Range, 0, len(recovered))
	for _, v := range recovered {
		if (v.Start >= it.Start && v.Start < it.End) || (v.End >= it.Start && v.End < it.End) {
			it.Start = min(it.Start, v.Start)
			it.End = max(it.End, v.End)
		} else {
			if v.Start == v.End {
				continue
			}
			res = append(res, v)
		}
	}
	res = append(res, it)
	sortRanges(res)
	return res
}

func sortRanges(res []util.Range) {
	slices.SortFunc(res, func(a, b util.Range) int {
		return cmp.Compare(a.Start, b.Start)
	})
}
