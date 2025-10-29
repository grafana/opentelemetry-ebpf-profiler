package symtab

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
)

func TestName(t *testing.T) {
	//=> try symbolize 446439 /usr/lib64/libc.so.6 09a2fc5776b5ee3709a2fc5776b5ee37 1db6a8
	path := "/usr/lib64/libc.so.6"
	//path := "/usr/lib/debug/.build-id/d7/eee7528bffbcc807b575cb94a47c0eeef71876.debug"
	//open, err := pfelf.Open(path)
	//require.NoError(t, err)
	ref := pfelf.NewReference(path, pfelf.SystemOpener)
	d, err := load(ref, "")
	require.NoError(t, err)
	dd := d.(*data)
	res := dd.symbolize(0xe84e0)
	require.Equal(t, "posix_fallocate", res)
}
