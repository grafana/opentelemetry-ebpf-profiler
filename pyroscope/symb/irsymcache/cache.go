package irsymcache

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"

	logkit "github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/process"
)

type Table interface {
	Lookup(addr uint64) ([]string, error)
	Close()
}

type TableFactory interface {
	ConvertTable(src *os.File, dst *os.File) error
	OpenTable(path string) (Table, error)
	Name() string
}

func NewTableFactory(gsym bool) TableFactory {
	if gsym {
		return GsymTableFactory{}
	}
	return TableTableFactory{}
}

type FSCache struct {
	f        TableFactory
	mu       sync.Mutex
	cacheDir string

	// fid -> size
	lru *LRUCache[libpf.FileID, int]

	jobs chan convertJob

	tables2 map[libpf.FileID]Table
	known   map[libpf.FileID]struct{}
	errored map[libpf.FileID]struct{}
	enabled bool
	l       logkit.Logger
}

func (c *FSCache) Cleanup() {
	_ = c.Close()
}

type convertJob struct {
	src *os.File
	dst *os.File

	result chan error
}

type Options struct {
	Enabled bool
	Path    string
	Size    int
}

func NewFSCache(l logkit.Logger, impl TableFactory, opt Options) (*FSCache, error) {
	l = logkit.With(l, "component", "irsymtab")
	_ = l.Log("enabled", opt.Enabled, "path", opt.Path, "size", opt.Size)
	lru := New[libpf.FileID, int](opt.Size, func(_ libpf.FileID, value int) int {
		return value
	})

	res := &FSCache{
		l:        l,
		f:        impl,
		cacheDir: opt.Path,
		lru:      lru,
		jobs:     make(chan convertJob, 1),
		tables2:  make(map[libpf.FileID]Table),
		known:    make(map[libpf.FileID]struct{}),
		errored:  make(map[libpf.FileID]struct{}),
		enabled:  opt.Enabled,
	}
	res.cacheDir = filepath.Join(res.cacheDir, impl.Name())
	err := os.MkdirAll(res.cacheDir, 0o700)
	if err != nil {
		return nil, err
	}
	lru.SetOnEvict(func(id libpf.FileID, sz int) {
		filePath := res.tableFilePath(id)
		_ = level.Debug(l).Log("msg", "symbcache evicting", "file", filePath, "size", sz)
		_ = os.Remove(filePath)
		res.mu.Lock()
		delete(res.known, id)
		res.mu.Unlock()
	})

	// list dir and add to cache
	err = filepath.Walk(res.cacheDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		id, err := libpf.FileIDFromString(filepath.Base(path))
		if err != nil {
			return nil
		}
		id2 := id.StringNoQuotes()
		if filepath.Base(path) != id2 {
			return nil
		}

		res.lru.Put(id, int(info.Size()))
		res.known[id] = struct{}{}
		return nil
	})
	if err != nil {
		return nil, err
	}

	go func() {
		i := 0
		for {
			time.Sleep(time.Minute)
			_ = l.Log("msg", "fscache lru size", "size", lru.Size())
			i++
			if i%10 == 0 {
				res.mu.Lock()
				res.errored = make(map[libpf.FileID]struct{})
				res.mu.Unlock()
			}
		}
	}()
	go func() { // todo shutdown
		convertLoop(res)
	}()

	return res, nil
}

func convertLoop(res *FSCache) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	for job := range res.jobs {
		job.result <- res.convertSync(job.src, job.dst)
	}
}

func (c *FSCache) Convert(fid libpf.FileID, elfRef *pfelf.Reference) {
	o, ok := elfRef.ELFOpener.(pfelf.RootFSOpener)
	if !ok {
		return
	}
	if !c.enabled {
		return
	}
	if elfRef.FileName() == process.VdsoPathName {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.isKnown(fid) {
		return
	}
	pid := 0
	if pp, ok := elfRef.ELFOpener.(process.Process); ok {
		pid = int(pp.PID())
	}
	l := logkit.With(c.l, "fid", fid.StringNoQuotes(),
		"elf", elfRef.FileName(),

		"pid", pid)
	t1 := time.Now()
	err := c.convert(l, fid, elfRef, o)
	if err != nil {
		l = level.Error(logkit.With(l, "err", err))
		c.errored[fid] = struct{}{}
	} else {
		l = level.Debug(l)
		c.known[fid] = struct{}{}
	}
	_ = l.Log("msg", "converted", "duration", time.Since(t1))
}

func (c *FSCache) convert(
	l logkit.Logger,
	fid libpf.FileID,
	elfRef *pfelf.Reference,
	o pfelf.RootFSOpener,
) error {
	var err error
	var dst *os.File
	var src *os.File

	_, _ = c.lru.Get(fid)
	tableFilePath := c.tableFilePath(fid)
	info, err := os.Stat(tableFilePath)
	if err == nil && info != nil {
		return nil
	}

	elf, err := c.getElf(l, elfRef)
	if err != nil {
		return err
	}
	defer elf.Close()
	debugLinkFileName := elf.DebuglinkFileName(elfRef.FileName(), elfRef)
	if debugLinkFileName != "" {
		src, err = o.OpenRootFSFile(debugLinkFileName)
		if err != nil {
			_ = level.Debug(l).Log("msg", "open debug file", "err", err)
		} else {
			defer src.Close()
		}
	}
	if src == nil {
		src = elf.OSFile()
	}
	if src == nil {
		return errors.New("failed to open elf os file")
	}

	dst, err = os.Create(tableFilePath)
	if err != nil {
		return err
	}
	defer dst.Close()

	err = c.convertAsync(src, dst)

	if err != nil {
		_ = os.Remove(tableFilePath)
		return err
	}

	sz := 0
	stat, _ := dst.Stat()
	if stat != nil {
		sz = int(stat.Size())
	}

	c.lru.Put(fid, sz)
	return nil
}

func (c *FSCache) getElf(l logkit.Logger, elfRef *pfelf.Reference) (*pfelf.File, error) {
	elf, err := elfRef.GetELF()
	if err == nil {
		return elf, nil
	}
	// todo why is this happening? mostly on my firefox sleeping processes
	if !errors.Is(err, syscall.ESRCH) && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	p, ok := elfRef.ELFOpener.(process.Process)
	if !ok {
		return nil, err
	}
	_, _ = p.GetMappings() // todo we have the mapping 3 stack frames above
	_ = level.Debug(l).Log("msg", "Get mappings", "proc", fmt.Sprintf("%+v", p))
	openELF, err := p.OpenELF(elfRef.FileName())
	if err != nil {
		_ = level.Error(l).Log("msg", "DEBUG ESRCH open elf", "err", err)
		return nil, err
	}

	return openELF, err
}

func (c *FSCache) convertAsync(src, dst *os.File) error {
	job := convertJob{src: src, dst: dst, result: make(chan error)}
	c.jobs <- job
	return <-job.result
}

func (c *FSCache) convertSync(src, dst *os.File) error {
	return c.f.ConvertTable(src, dst)
}

func (c *FSCache) tableFilePath(fid libpf.FileID) string {
	return filepath.Join(c.cacheDir, fid.StringNoQuotes())
}

var errUnknwnFile = errors.New("unknown file")

func (c *FSCache) Lookup(fid libpf.FileID, addr uint64) ([]string, error) {
	if !c.enabled {
		return nil, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.isKnown(fid) {
		return nil, errUnknwnFile
	}
	table, ok := c.tables2[fid]
	if ok {
		return table.Lookup(addr)
	}
	path := c.tableFilePath(fid)
	table, err := c.f.OpenTable(path)
	if err != nil {
		_ = os.Remove(path)
		return nil, err
	}
	c.tables2[fid] = table
	return table.Lookup(addr)
}

func (c *FSCache) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, table := range c.tables2 {
		table.Close()
	}
	clear(c.tables2)
	return nil
}

func (c *FSCache) isKnown(fid libpf.FileID) bool {
	if _, ok := c.known[fid]; ok {
		return true
	}
	if _, ok := c.errored[fid]; ok {
		return true
	}
	return false
}
