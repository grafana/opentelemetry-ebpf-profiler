package symtab

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
)

func TestName(t *testing.T) {
	//=> try symbolize 446439 /usr/lib64/libc.so.6 09a2fc5776b5ee3709a2fc5776b5ee37 1db6a8
	open, err := pfelf.Open("/usr/lib64/libc.so.6")
	require.NoError(t, err)
	d, err := load(open, "")
	require.NoError(t, err)
	dd := d.(*data)
	res := dd.symbolize(0xe84e0)
	require.Equal(t, "posix_fallocate", res)

}
