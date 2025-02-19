package irsymcache

import (
	"os"

	"go.opentelemetry.io/ebpf-profiler/pyroscope/symb/gsym"
)

type GsymTableFactory struct {
}

func (g GsymTableFactory) ConvertTable(src, dst *os.File) error {
	return gsym.FDToGSym(src, dst)
}

func (g GsymTableFactory) OpenTable(path string) (Table, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	table, err := gsym.NewGsymWithReader(f)
	if err != nil {
		return nil, err
	}
	return table, nil
}

func (g GsymTableFactory) Name() string {
	return "gsym"
}
