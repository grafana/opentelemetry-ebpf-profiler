package cache

import (
	"errors"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/reporter/pyroscope/symb/gsym"
	symbtable "go.opentelemetry.io/ebpf-profiler/reporter/pyroscope/symb/table"
	"runtime"
	"strings"
	"time"

	"os"
	"path/filepath"
	"sync"
	"syscall"
)

type FileID libpf.FileID
type FSCache struct {
	mu       sync.Mutex
	cacheDir string

	// fid -> size
	lru *LRUCache[FileID, int]

	jobs chan convertJob

	tables     map[FileID]*symbtable.Table
	gsymTables map[FileID]*gsym.Gsym
	known      map[FileID]struct{}
	errored    map[FileID]struct{}
	enabled    bool
	useGsym    bool
}

type convertJob struct {
	src *os.File
	dst *os.File

	result chan error
}

// todo metric of inmemory range table size
// todo  convert only if we need it.
func NewFSCache(fsSize int, path string, enabled bool) *FSCache {
	log.Infof("fscache enabled %v %s %d\n", enabled, path, fsSize)
	//sz := 2 * 1024 * 1024 * 1024
	lru := New[FileID, int](fsSize, func(key FileID, value int) int {
		return value
	})

	res := &FSCache{
		cacheDir:   path, //"/data/symb-cache",
		lru:        lru,
		jobs:       make(chan convertJob, 1),
		tables:     make(map[FileID]*symbtable.Table),
		gsymTables: make(map[FileID]*gsym.Gsym),
		known:      make(map[FileID]struct{}),
		errored:    make(map[FileID]struct{}),
		enabled:    enabled,
		useGsym:    true,
	}
	if res.useGsym {
		res.cacheDir = filepath.Join(res.cacheDir, "gsym")
	} else {
		res.cacheDir = filepath.Join(res.cacheDir, "table")
	}
	os.MkdirAll(res.cacheDir, 0700)
	lru.SetOnEvict(func(id FileID, v int) {
		filePath := res.tableFilePath(id)
		log.Infof("symbcache evicting  %s %s\n", id, filePath)
		_ = os.Remove(filePath)
		res.mu.Lock()
		delete(res.known, id)
		res.mu.Unlock()
	})

	// list dir and add to cache
	_ = filepath.Walk(res.cacheDir, func(path string, info os.FileInfo, err error) error {
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

		res.lru.Put(FileID(id), int(info.Size()))
		res.known[FileID(id)] = struct{}{}
		return nil
	})

	go func() {
		i := 0
		for {
			time.Sleep(time.Minute)
			log.Debugf("fscache lru size %d\n", lru.Size())
			i++
			if i%10 == 0 {
				res.mu.Lock()
				res.errored = make(map[FileID]struct{})
				res.mu.Unlock()
			}
		}
	}()
	go func() {
		convertLoop(res)
	}()

	return res
}

func convertLoop(res *FSCache) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	for job := range res.jobs {
		job.result <- res.convertSync(job.src, job.dst)
	}
}

// todo consider mvoe this to reporter ExecutableInfo cache?
func (c *FSCache) Convert(fid libpf.FileID, elfRef *pfelf.Reference) {
	if !c.enabled {
		return
	}
	if strings.Contains(elfRef.FileName(), "linux-vdso.1") {
		return
	}
	l := log.WithField("fid", fid.StringNoQuotes()).
		WithField("elf", elfRef.FileName()).
		WithField("component", "symb-fscache")
	l.Debug("fscache open")
	var err error
	var dst *os.File
	var src *os.File

	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.known[FileID(fid)]; ok {
		return
	}
	if _, ok := c.errored[FileID(fid)]; ok {
		return
	}

	_, _ = c.lru.Get(FileID(fid))
	tableFilePath := c.tableFilePath(FileID(fid))
	info, err := os.Stat(tableFilePath)
	if err == nil && info != nil {
		return
	}

	o, ok := elfRef.ELFOpener.(pfelf.RootFSOpener)
	if !ok {
		return
	}

	elf, err := c.getElf(l, elfRef)
	if err != nil {
		c.errored[FileID(fid)] = struct{}{}
		l.Errorf("failed to open elf : %s\n", err.Error())
		return
	}
	defer elf.Close()
	debugLinkFileName := elf.DebuglinkFileName(elfRef.FileName(), elfRef)
	if debugLinkFileName != "" {
		src, err = o.OpenRootFSFile(debugLinkFileName)
		if err != nil {
			l.Debugf("open debug file error  %s\n", err.Error())
		} else {
			defer src.Close()
		}
	}
	if src == nil {
		src = elf.OSFile()
	}
	if src == nil {
		l.Errorf("failed to open elf os file  \n")
		c.errored[FileID(fid)] = struct{}{}
		return
	}

	dst, err = os.Create(tableFilePath)
	if err != nil {
		l.Errorf("err create %s %s \n", tableFilePath, err.Error())
		return
	}
	defer dst.Close()

	t1 := time.Now()

	err = c.convertAsync(src, dst)

	if err != nil {
		l.Errorf("convert took %s err : %v \n", time.Since(t1), err)
		c.errored[FileID(fid)] = struct{}{}
		_ = os.Remove(tableFilePath)
		return
	}

	sz := 0
	stat, _ := dst.Stat()
	if stat != nil {
		sz = int(stat.Size())
	}
	l.Debugf(" convert took %s size: %v , err : %v \n", time.Since(t1), sz, err)

	c.lru.Put(FileID(fid), sz)
	c.known[FileID(fid)] = struct{}{}
}

func (c *FSCache) getElf(l *log.Entry, elfRef *pfelf.Reference) (*pfelf.File, error) {
	elf, err := elfRef.GetELF()
	if err == nil {
		return elf, nil
	}
	//todo why is this happening? mostly on my firefox sleeping processes
	if !errors.Is(err, syscall.ESRCH) && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	p, ok := elfRef.ELFOpener.(process.Process)
	if !ok {
		return nil, err
	}
	_, _ = p.GetMappings() //todo we have the mapping 3 stack frames above
	l.Debugf("Get mappings  %+v\n", p)
	openELF, err := p.OpenELF(elfRef.FileName())
	if err != nil {
		l.Errorf("DEBUG ESRCH open elf  %v\n", err)
		return nil, err
	}

	return openELF, err
}

func (c *FSCache) convertAsync(src *os.File, dst *os.File) error {

	job := convertJob{src: src, dst: dst, result: make(chan error)}
	c.jobs <- job
	return <-job.result
}

func (c *FSCache) convertSync(src *os.File, dst *os.File) error {
	//return table.FDToTable(src, nil, dst)
	return gsym.FDToGSym(src, dst)
}

func (c *FSCache) tableFilePath(fid FileID) string {
	return filepath.Join(c.cacheDir, fid.StringNoQuotes())
}

func (c *FSCache) Lookup(pid int64, fid FileID, addr uint64, symbols []string) []string {
	if !c.enabled {
		return symbols[:0]
	}
	if c.useGsym {
		return c.LookupGsym(pid, fid, addr, symbols)
	}
	return c.LookupTable(pid, fid, addr, symbols)
}

func (c *FSCache) LookupTable(pid int64, fid FileID, addr uint64, symbols []string) []string {
	if !c.enabled {
		return symbols[:0]
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	table, ok := c.tables[fid]
	if ok {
		return table.Lookup(addr, symbols)
	}
	table, err := symbtable.OpenPath(c.tableFilePath(fid))
	if err != nil {
		return symbols[:0]
	}
	c.tables[fid] = table
	return table.Lookup(addr, symbols)
}

func (c *FSCache) LookupGsym(pid int64, fid FileID, addr uint64, symbols []string) []string {
	if !c.enabled {
		return symbols[:0]
	}
	symbols = symbols[:0]
	c.mu.Lock()
	defer c.mu.Unlock()
	table, ok := c.gsymTables[fid]
	if ok {
		res, err := table.LookupAddress(addr)
		if err != nil {
			return symbols[:0]
		}
		for _, location := range res.Locations {
			symbols = append(symbols, location.Name)
		}
		return symbols
	}
	path := c.tableFilePath(fid)
	f, err := os.Open(path)
	if err != nil {
		return symbols[:0]
	}
	table, err = gsym.NewGsymWithReader(f)
	if err != nil {
		return symbols[:0]
	}
	c.gsymTables[fid] = table
	res, err := table.LookupAddress(addr)
	if err != nil {
		return symbols[:0]
	}
	for _, location := range res.Locations {
		symbols = append(symbols, location.Name)
	}
	return symbols
}

func (c *FSCache) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, table := range c.tables {
		table.Close()
	}
	clear(c.tables)
	return nil
}

func (c *FSCache) Enabled() bool {
	return c.enabled
}
