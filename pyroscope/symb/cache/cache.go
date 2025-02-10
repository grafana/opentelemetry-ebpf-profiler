package cache

import (
	"errors"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/process"
	gsym2 "go.opentelemetry.io/ebpf-profiler/pyroscope/symb/gsym"
	symbtable "go.opentelemetry.io/ebpf-profiler/pyroscope/symb/table"
	"runtime"
	"strings"
	"time"

	"os"
	"path/filepath"
	"sync"
	"syscall"
)

type FSCache struct {
	mu       sync.Mutex
	cacheDir string

	// fid -> size
	lru *LRUCache[libpf.FileID, int]

	jobs chan convertJob

	tables     map[libpf.FileID]*symbtable.Table
	gsymTables map[libpf.FileID]*gsym2.Gsym
	known      map[libpf.FileID]struct{}
	errored    map[libpf.FileID]struct{}
	enabled    bool
	useGsym    bool
}

func (c *FSCache) Cleanup() {
	_ = c.Close()
}

type convertJob struct {
	src *os.File
	dst *os.File

	result chan error
}

func NewFSCache(fsSize int, path string, enabled bool) (*FSCache, error) {
	log.Infof("fscache enabled %v %s %d\n", enabled, path, fsSize)
	lru := New[libpf.FileID, int](fsSize, func(key libpf.FileID, value int) int {
		return value
	})

	res := &FSCache{
		cacheDir:   path,
		lru:        lru,
		jobs:       make(chan convertJob, 1),
		tables:     make(map[libpf.FileID]*symbtable.Table),
		gsymTables: make(map[libpf.FileID]*gsym2.Gsym),
		known:      make(map[libpf.FileID]struct{}),
		errored:    make(map[libpf.FileID]struct{}),
		enabled:    enabled,
		useGsym:    true,
	}
	if res.useGsym {
		res.cacheDir = filepath.Join(res.cacheDir, "gsym")
	} else {
		res.cacheDir = filepath.Join(res.cacheDir, "table")
	}
	err := os.MkdirAll(res.cacheDir, 0700)
	if err != nil {
		return nil, err
	}
	lru.SetOnEvict(func(id libpf.FileID, v int) {
		filePath := res.tableFilePath(id)
		log.Infof("symbcache evicting  %s %s\n", id, filePath)
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

		res.lru.Put(libpf.FileID(id), int(info.Size()))
		res.known[libpf.FileID(id)] = struct{}{}
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
				res.errored = make(map[libpf.FileID]struct{})
				res.mu.Unlock()
			}
		}
	}()
	go func() { //todo shutdown
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

	if _, ok := c.known[libpf.FileID(fid)]; ok {
		return
	}
	if _, ok := c.errored[libpf.FileID(fid)]; ok {
		return
	}

	_, _ = c.lru.Get(libpf.FileID(fid))
	tableFilePath := c.tableFilePath(libpf.FileID(fid))
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
		c.errored[libpf.FileID(fid)] = struct{}{}
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
		c.errored[libpf.FileID(fid)] = struct{}{}
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
		c.errored[libpf.FileID(fid)] = struct{}{}
		_ = os.Remove(tableFilePath)
		return
	}

	sz := 0
	stat, _ := dst.Stat()
	if stat != nil {
		sz = int(stat.Size())
	}
	l.Debugf(" convert took %s size: %v , err : %v \n", time.Since(t1), sz, err)

	c.lru.Put(libpf.FileID(fid), sz)
	c.known[libpf.FileID(fid)] = struct{}{}
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
	return gsym2.FDToGSym(src, dst)
}

func (c *FSCache) tableFilePath(fid libpf.FileID) string {
	return filepath.Join(c.cacheDir, fid.StringNoQuotes())
}

func (c *FSCache) Lookup(pid int64, fid libpf.FileID, addr uint64) []string {
	if !c.enabled {
		return nil
	}
	if c.useGsym {
		return c.LookupGsym(pid, fid, addr, nil)
	}
	return c.LookupTable(pid, fid, addr, nil)
}

func (c *FSCache) LookupTable(pid int64, fid libpf.FileID, addr uint64, symbols []string) []string {
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

func (c *FSCache) LookupGsym(pid int64, fid libpf.FileID, addr uint64, symbols []string) []string {
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
	table, err = gsym2.NewGsymWithReader(f)
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

//func (c *FSCache) Enabled() bool {
//	return c.enabled
//}
