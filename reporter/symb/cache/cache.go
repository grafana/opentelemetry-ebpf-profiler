package cache

import (
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/reporter/symb"
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

	tables  map[FileID]*symb.Table
	known   map[FileID]struct{}
	enabled bool
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
		cacheDir: path, //"/data/symb-cache",
		lru:      lru,
		jobs:     make(chan convertJob, 1),
		tables:   make(map[FileID]*symb.Table),
		known:    make(map[FileID]struct{}),
		enabled:  enabled,
	}
	os.MkdirAll(res.cacheDir, 0700)
	lru.SetOnEvict(func(id FileID, v int) {
		_ = os.Remove(res.tableFilePath(id))
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
		for {
			time.Sleep(time.Minute)
			fmt.Printf("fscache lru size %d\n", lru.Size())
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
	logtag := fmt.Sprintf("fid=%s elf=%s", fid.StringNoQuotes(), elfRef.FileName())
	//fmt.Printf("fscache open  %s %s\n", fid.StringNoQuotes(), elfRef.FileName())
	var err error
	var dst *os.File
	var src *os.File

	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.known[FileID(fid)]; ok {
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

	elf, err := elfRef.GetELF()
	if err != nil {
		fmt.Printf("failed to open elf %s: %s\n", logtag, err.Error())
		return
	}
	debugLinkFileName := elf.DebuglinkFileName(elfRef.FileName(), elfRef)
	if debugLinkFileName != "" {
		src, err = o.OpenRootFSFile(debugLinkFileName)
		if err != nil {
			fmt.Printf("open debug file %s %s\n", logtag, err.Error())
		}
	}

	if src == nil {
		src, err = o.OpenRootFSFile(elfRef.FileName())
		if err != nil {
			if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ESRCH) {
				//todo if /proc/{pid} exists, try to open mapping? or try to open file from file namespace?
				return
			}
			fmt.Printf("err open %s\n", err.Error())
			return
		}
	}

	defer src.Close()

	dst, err = os.Create(tableFilePath)
	if err != nil {
		fmt.Printf("err create %s %s %s %s\n", fid.StringNoQuotes(), tableFilePath, elfRef.FileName(), err.Error())
		return
	}
	defer dst.Close()

	t1 := time.Now()
	fmt.Printf("convertAsync %s %s\n", fid.StringNoQuotes(), elfRef.FileName())
	if elfRef.FileName() == "/bin/prometheus" {
		return
	}
	err = c.convertAsync(src, dst)

	if err != nil {
		fmt.Printf("%s convert took %s err : %v \n", logtag, time.Since(t1), err)
		_ = os.Remove(tableFilePath)
		return
	}

	sz := 0
	stat, _ := dst.Stat()
	if stat != nil {
		sz = int(stat.Size())
	}
	fmt.Printf("%s convert took %s size: %v , err : %v \n", logtag, time.Since(t1), sz, err)

	c.lru.Put(FileID(fid), sz)
	c.known[FileID(fid)] = struct{}{}
}

func (c *FSCache) convertAsync(src *os.File, dst *os.File) error {

	job := convertJob{src: src, dst: dst, result: make(chan error)}
	c.jobs <- job
	return <-job.result
}

func (c *FSCache) convertSync(src *os.File, dst *os.File) error {
	return symb.FDToTable(src, nil, dst)
}

func (c *FSCache) tableFilePath(fid FileID) string {
	return filepath.Join(c.cacheDir, fid.StringNoQuotes())
}

//func (pm *ProcessManager) symbConvert(trace *host.Trace, mapping Mapping, fileID libpf.FileID) {
//	if pm.symb == nil {
//		return
//	}
//	pr := process.New(trace.PID)
//	elfRef := pfelf.NewReference(mapping.FilePath, pr)
//	defer elfRef.Close()
//	pm.symb.Convert(fileID, elfRef)
//}

func (c *FSCache) Lookup(pid int64, fid FileID, addr uint64, symbols []string) []string {
	if !c.enabled {
		return symbols[:0]
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	table, ok := c.tables[fid]
	if ok {
		return table.Lookup(addr, symbols)
	}
	table, err := symb.OpenPath(c.tableFilePath(fid))
	if err != nil {
		return symbols[:0]
	}
	c.tables[fid] = table
	return table.Lookup(addr, symbols)
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
