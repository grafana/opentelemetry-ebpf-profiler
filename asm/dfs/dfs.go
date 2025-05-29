package dfs

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"go.opentelemetry.io/ebpf-profiler/util"
)

type BasicBlock struct {
	index    int
	start    uint64
	end      uint64
	explored bool

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
	typ  EdgeTypeFlags
	edge *BasicBlock
}

func (r *BasicBlock) String() string {
	return fmt.Sprintf("[%x;%x)", r.start, r.end)
}

func (r *BasicBlock) Explored() {
	r.explored = true
}

func (r *BasicBlock) Size() uint64 {
	return r.end - r.start
}
func (r *BasicBlock) Position() (uint64, bool) {
	return r.end, r.explored
}

func (b *BasicBlock) Start() uint64 {
	return b.start
}

func (d *DFS) PeekUnexplored() *BasicBlock {
	for _, r := range d.blocks {
		if !r.explored {
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
			start:    start,
			end:      start,
			explored: false,
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
			start:    start,
			end:      l.end,
			explored: l.explored,
			edges:    l.edges,
		}
		l.explored = true
		l.end = start
		l.edges = []Edge{{EdgeTypeFallThrough, r}}
	} else {
		r = &BasicBlock{
			start:    start,
			end:      start,
			explored: false,
		}
	}
	d.blocks = slices.Insert(d.blocks, i+1, r)
	d.reassignIndexes()
	return r
}

type EdgeTypeFlags int

const (
	EdgeTypeFallThrough = EdgeTypeFlags(1)
	EdgeTypeJump        = EdgeTypeFlags(2)
)

// todo add two testcases wheen we add an edge from block A block B and then one of them is split
func (d *DFS) AddEdge(from *BasicBlock, to *BasicBlock, et EdgeTypeFlags) {

	from.explored = true
	if from.findEdge(to) != nil {
		return
	}
	from.edges = append(from.edges, Edge{et, to})
}

func (d *DFS) AddInstruction(r *BasicBlock, l int, et EdgeTypeFlags) error {
	if r.explored {
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
		r.explored = true
		if (et & EdgeTypeFallThrough) != 0 {
			d.AddEdge(r, next, EdgeTypeFallThrough)
		}
		return nil
	}
	return errors.New("overlap")
}

func (d *DFS) reassignIndexes() {
	for i := 0; i < len(d.blocks); i++ {
		d.blocks[i].index = i
	}
}

func (d *DFS) Ranges() []util.Range {
	// consider excluding blocks that contain ud or falls-through into a block with ud
	if len(d.blocks) == 0 {
		return nil
	}
	res := make([]util.Range, 0, 4)
	it := util.Range{
		Start: d.blocks[0].start,
		End:   d.blocks[0].end,
	}
	for j := 1; j < len(d.blocks); j++ {
		jit := d.blocks[j]
		if jit.start == it.End || jit.start-it.End < 16 {
			it.End = jit.end
		} else {
			res = append(res, it)
			it = util.Range{
				Start: jit.start,
				End:   jit.end,
			}
		}
	}
	res = append(res, it)
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
		if edge != nil && (edge.typ&EdgeTypeFallThrough == EdgeTypeFallThrough) {
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
