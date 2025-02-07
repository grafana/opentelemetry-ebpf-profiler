package ffi

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
)

type mycb struct {
	cnt int
}

func (m *mycb) VisitRange(elfVA uint64, length uint32, depth uint32, function string) {
	m.cnt++
}
func TestRaneExtractor(t *testing.T) {

	f, err := os.Open("/proc/self/exe")
	require.NoError(t, err)

	v := new(mycb)
	err = RangeExtractor(f, v)
	require.NoError(t, err)
	assert.Greater(t, v.cnt, 0)
}
