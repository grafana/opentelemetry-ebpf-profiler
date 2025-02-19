package irsymcache

import (
	"os"

	"go.opentelemetry.io/ebpf-profiler/pyroscope/symb/table"
)

type TableTableFactory struct {
}

func (t TableTableFactory) ConvertTable(src, dst *os.File) error {
	return table.FDToTable(src, dst)
}

func (t TableTableFactory) OpenTable(path string) (Table, error) {
	return table.OpenPath(path)
}

func (t TableTableFactory) Name() string {
	return table.VersionName()
}
