package amd

import (
	"encoding/hex"
	"errors"
	"fmt"

	"go.opentelemetry.io/ebpf-profiler/asm/dfs"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"golang.org/x/arch/x86/x86asm"
)

func Explore(ef *pfelf.File, d *dfs.DFS, indirectJumps map[uint64]struct{}) error {
	for {
		it := d.PeekUnexplored()

		if it == nil {
			break
		}
		const blockLimit = 8 * 1024 // 2700 observed
		if d.BasicBlockCount() >= blockLimit {
			return errors.New("too many blocks")
		}

		codeBuf := [16]byte{}
		for {
			pos, explored := it.Position()
			if explored {
				break
			}
			et := dfs.EdgeTypeFlags(0)
			if _, err := ef.ReadAt(codeBuf[:], int64(pos)); err != nil {
				return err
			}
			if ok, sz := DecodeSkippable(codeBuf[:]); ok {
				if err := d.AddInstruction(it, sz, et); err != nil {
					return err
				}
				continue
			}
			insn, err := x86asm.Decode(codeBuf[:], 64)
			if err != nil {
				return err
			}
			rip := pos
			jump := IsJump(insn.Op)
			conditionalJump := !(insn.Op == x86asm.JMP || insn.Op == x86asm.RET)
			mayFallThrough := !jump || conditionalJump
			if mayFallThrough {
				et |= dfs.EdgeTypeFallThrough
			}
			if err = d.AddInstruction(it, insn.Len, et); err != nil {
				return err
			}

			rip += uint64(insn.Len)

			if jump {
				it.Explored()
				if conditionalJump {
					e := d.AddBasicBlock(rip)
					d.AddEdge(it, e, dfs.EdgeTypeFallThrough)
				}
				if insn.Op != x86asm.RET {
					switch typed := insn.Args[0].(type) {
					case x86asm.Rel:
						dst := uint64(int64(rip) + int64(typed))
						to := d.AddBasicBlock(dst)
						if dst == 0x2ffb13 {
							fmt.Printf("bp %s\n", it.String())
						}
						d.AddEdge(it, to, dfs.EdgeTypeJump)
					case x86asm.Reg, x86asm.Mem:
						if indirectJumps != nil {
							indirectJumps[pos] = struct{}{}
						}
					default:
						return fmt.Errorf("unhandled jump: %s %s \n", hex.EncodeToString(codeBuf[:]), insn.String())
					}
				}
				break
			}
		}
	}
	return nil
}
