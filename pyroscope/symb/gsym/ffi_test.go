package gsym

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestBuildInlineInfo(t *testing.T) {
	ii := buildInlineInfo([]rangeEntry{
		{va: 0xcafe000, length: 0x100, depth: 0, fun: 1},
		{va: 0xcafe010, length: 0x10, depth: 1, fun: 2},
		{va: 0xcafe012, length: 0x2, depth: 2, fun: 3},
		{va: 0xcafe030, length: 0x10, depth: 1, fun: 4},
		{va: 0xcafe032, length: 0x2, depth: 2, fun: 5},
	})
	assert.NotNil(t, ii)
	assert.Len(t, ii.Children, 2)
	assert.Len(t, ii.Children[0].Children, 1)
	assert.Len(t, ii.Children[0].Children[0].Children, 0)
	assert.Len(t, ii.Children[1].Children, 1)
	assert.Len(t, ii.Children[1].Children[0].Children, 0)
	assert.Equal(t, StringOffset(1), ii.Name)
	assert.Equal(t, StringOffset(2), ii.Children[0].Name)
	assert.Equal(t, StringOffset(3), ii.Children[0].Children[0].Name)
	assert.Equal(t, StringOffset(4), ii.Children[1].Name)
	assert.Equal(t, StringOffset(5), ii.Children[1].Children[0].Name)

}
