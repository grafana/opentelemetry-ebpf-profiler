package dfs

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestDFSAddInstructionReachNextBB(t *testing.T) {
	d := DFS{}
	b1 := d.AddBasicBlock(10)
	b2 := d.AddBasicBlock(0)
	require.Len(t, d.blocks, 2)
	assert.EqualValues(t, 1, b1.index)
	assert.EqualValues(t, 0, b2.index)
	err := d.AddInstruction(b2, 10, EdgeTypeFallThrough)
	require.NoError(t, err)
	assert.True(t, b2.explored)
	assert.NotNil(t, b2.findEdge(b1))
}

func TestDFSAddInstructionReachNextBBOverlaps(t *testing.T) {
	d := DFS{}
	b1 := d.AddBasicBlock(10)
	b2 := d.AddBasicBlock(0)
	require.Len(t, d.blocks, 2)
	assert.EqualValues(t, 1, b1.index)
	assert.EqualValues(t, 0, b2.index)
	err := d.AddInstruction(b2, 11, EdgeTypeFallThrough)
	require.Error(t, err)
}

func TestDFSAddBBMatchStart(t *testing.T) {
	d := DFS{}
	b1 := d.AddBasicBlock(10)
	b2 := d.AddBasicBlock(10)
	assert.Equal(t, b1, b2)
}

func TestDFSAddBBNoMatchInsert(t *testing.T) {
	d := DFS{}
	_ = d.AddBasicBlock(10)
	_ = d.AddBasicBlock(100)
	_ = d.AddBasicBlock(50)
	require.Len(t, d.blocks, 3)

}

func TestDFSAddBBSplitExplored(t *testing.T) {
	d := DFS{}
	b1 := d.AddBasicBlock(0)
	err := d.AddInstruction(b1, 10, EdgeTypeFallThrough)
	require.NoError(t, err)
	b1.Explored()
	b2 := d.AddBasicBlock(5)
	assert.True(t, b2.explored)
	assert.True(t, b1.explored)
	assert.NotEqual(t, b1, b2)
	assert.EqualValues(t, 0, b1.start)
	assert.EqualValues(t, 5, b1.end)
	assert.EqualValues(t, 5, b2.start)
	assert.EqualValues(t, 10, b2.end)
	assert.NotNil(t, b1.findEdge(b2))

	assert.Len(t, d.blocks, 2)
}

func TestDFSAddBBSplitExploredNonLast(t *testing.T) {
	d := DFS{}
	b1 := d.AddBasicBlock(0)
	_ = d.AddBasicBlock(100)
	err := d.AddInstruction(b1, 10, EdgeTypeFallThrough)
	require.NoError(t, err)
	b1.Explored()
	b2 := d.AddBasicBlock(5)
	assert.True(t, b2.explored)
	assert.True(t, b1.explored)
	assert.NotEqual(t, b1, b2)
	assert.EqualValues(t, 0, b1.start)
	assert.EqualValues(t, 5, b1.end)
	assert.EqualValues(t, 5, b2.start)
	assert.EqualValues(t, 10, b2.end)
	assert.NotNil(t, b1.findEdge(b2), b2)
	assert.Len(t, d.blocks, 3)
}

func TestDFSAddBBSplitUnexplored(t *testing.T) {
	d := DFS{}
	b1 := d.AddBasicBlock(0)
	err := d.AddInstruction(b1, 10, EdgeTypeFallThrough)
	require.NoError(t, err)
	b2 := d.AddBasicBlock(5)
	assert.False(t, b2.explored)
	assert.True(t, b1.explored)
	assert.NotEqual(t, b1, b2)
	assert.EqualValues(t, 0, b1.start)
	assert.EqualValues(t, 5, b1.end)
	assert.EqualValues(t, 5, b2.start)
	assert.EqualValues(t, 10, b2.end)
	assert.NotNil(t, b1.findEdge(b2))
	assert.Len(t, d.blocks, 2)
}
