package dfs

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"go.opentelemetry.io/ebpf-profiler/util"
)

const flagExplored = 1
const flagCallNoReturn = 2
const flagUD = 4

type BasicBlock struct {
	index int32
	flags uint32
	start uint64
	end   uint64

	edges []Edge
}

func (b *BasicBlock) findEdge(to *BasicBlock) *Edge {
	for i, edge := range b.edges {
		if edge.edge == to {
			return &b.edges[i]
		}
	}
	return nil
}

type Edge struct {
	typ  EdgeType
	edge *BasicBlock
}

func (r *BasicBlock) String() string {
	return fmt.Sprintf("[%x;%x)", r.start, r.end)
}

func (r *BasicBlock) MarkExplored() {
	r.flags |= flagExplored
}

func (r *BasicBlock) MarkCallNoReturn() {
	r.flags |= flagCallNoReturn
}

func (r *BasicBlock) MarkUD() {
	r.flags |= flagUD
}

func (r *BasicBlock) UD() bool {
	return (r.flags & flagUD) == flagUD
}

func (r *BasicBlock) CallDoesNotReturn() bool {
	return (r.flags & flagCallNoReturn) == flagCallNoReturn
}
func (r *BasicBlock) Explored() bool {
	return (r.flags & flagExplored) == flagExplored
}
func (r *BasicBlock) Size() uint64 {
	return r.end - r.start
}
func (r *BasicBlock) Position() (uint64, bool) {
	return r.end, r.Explored()
}

func (b *BasicBlock) Start() uint64 {
	return b.start
}

func (d *DFS) PeekUnexplored() *BasicBlock {
	for _, r := range d.blocks {
		if !r.Explored() {
			return r
		}
	}
	return nil
}

type DFS struct {
	blocks []*BasicBlock
}

func (d *DFS) BasicBlockCount() int {
	return len(d.blocks)
}

func (d *DFS) String() string {
	ss := make([]string, 0, len(d.blocks))
	for _, r := range d.blocks {
		ss = append(ss, r.String())
	}
	return fmt.Sprintf("DFS %s", strings.Join(ss, ", "))
}

func (d *DFS) FindBasicBlock(at uint64) *BasicBlock {
	i := sort.Search(len(d.blocks), func(j int) bool {
		return d.blocks[j].start > at
	})
	i--
	if i < 0 {
		return nil
	}
	l := d.blocks[i]
	if l.start == at {
		return l
	}
	if at > l.start && at < l.end {
		return l
	}
	return nil
}

func (d *DFS) AddBasicBlock(start uint64) *BasicBlock {
	i := sort.Search(len(d.blocks), func(j int) bool {
		return d.blocks[j].start > start
	})
	i--
	if i < 0 {
		r := &BasicBlock{
			start: start,
			end:   start,
		}
		d.blocks = slices.Insert(d.blocks, 0, r)
		d.reassignIndexes()
		return r
	}
	l := d.blocks[i]
	if l.start == start {
		return l
	}
	var r *BasicBlock
	if start > l.start && start < l.end {
		r = &BasicBlock{
			start: start,
			end:   l.end,
			flags: l.flags,
			edges: l.edges,
		}
		l.MarkExplored()
		l.end = start
		l.edges = []Edge{{EdgeTypeFallThrough, r}}
	} else {
		r = &BasicBlock{
			start: start,
			end:   start,
		}
	}
	d.blocks = slices.Insert(d.blocks, i+1, r)
	d.reassignIndexes()
	return r
}

type EdgeType int

const (
	EdgeTypeFallThrough = EdgeType(1)
	EdgeTypeJump        = EdgeType(2)
)

func (d *DFS) AddEdge(from *BasicBlock, to *BasicBlock, et EdgeType) {
	from.MarkExplored()
	if from.findEdge(to) != nil {
		return
	}
	from.edges = append(from.edges, Edge{et, to})
}

func (d *DFS) AddInstruction(r *BasicBlock, l int, mayFallThrough bool) error {
	if r.Explored() {
		return errors.New("explored")
	}
	r.end += uint64(l)
	end := r.end
	nextIndex := int(r.index) + 1
	if nextIndex >= len(d.blocks) {
		return nil
	}
	next := d.blocks[nextIndex]
	if end < next.start {
		return nil
	}
	if end == next.start {
		r.MarkExplored()
		if mayFallThrough {
			d.AddEdge(r, next, EdgeTypeFallThrough)
		}
		return nil
	}
	return errors.New("overlap")
}

func (d *DFS) reassignIndexes() {
	for i := 0; i < len(d.blocks); i++ {
		d.blocks[i].index = int32(i)
	}
}

func (d *DFS) Ranges() []util.Range {
	return d.RangesWithFilter(func(_ *BasicBlock) bool {
		return true
	})
}

func (d *DFS) RangesWithFilter(f func(b *BasicBlock) bool) []util.Range {
	res := make([]util.Range, 0, 4)
	for j := 0; j < len(d.blocks); j++ {
		jit := d.blocks[j]
		if !f(jit) {
			continue
		}
		if len(res) == 0 {
			res = append(res, util.Range{
				Start: jit.start,
				End:   jit.end,
			})
			continue
		}
		it := &res[len(res)-1]
		if jit.start == it.End || jit.start-it.End < 32 {
			it.End = jit.end
		} else {
			res = append(res, util.Range{
				Start: jit.start,
				End:   jit.end,
			})
		}
	}
	return res
}

// todo test
func (d *DFS) FallThroughBlocksTo(block *BasicBlock, n int) []*BasicBlock {
	it := block
	var res []*BasicBlock = make([]*BasicBlock, 0, n)
	res = append(res, block)
	n--
	for n > 0 {
		prevIndex := it.index - 1
		if prevIndex <= 0 {
			break
		}
		prev := d.blocks[prevIndex]
		edge := prev.findEdge(it)
		if edge != nil && edge.typ == EdgeTypeFallThrough {
			res = append(res, prev)
			it = prev
			n--
		} else {
			break
		}
	}
	slices.Reverse(res)
	return res
}
