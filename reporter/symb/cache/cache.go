package cache

import (
	"errors"
	"fmt"
	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/reporter/symb"
	"runtime"
	"time"

	"os"
	"path/filepath"
	"sync"
	"syscall"
)

type FileID host.FileID
type FSCache struct {
	mu       sync.Mutex
	cacheDir string

	// fid -> size
	lru *LRUCache[FileID, int]

	jobs chan convertJob
}

type convertJob struct {
	src *os.File
	dst *os.File

	result chan error
}

// todo metric of inmemory range table size
// todo keep a link to a process, retrun lazy table, convert only if we need it.
func NewFSCache() *FSCache {
	sz := 2 * 1024 * 1024 * 1024
	lru := New[FileID, int](sz, func(key FileID, value int) int {
		return value
	})

	res := &FSCache{
		cacheDir: "/data/symb-cache",
		lru:      lru,
		jobs:     make(chan convertJob, 1),
	}
	os.MkdirAll(res.cacheDir, 0700)
	lru.SetOnEvict(func(id FileID, v int) {
		_ = os.Remove(res.tableFilePath(host.FileID(id)))
	})

	// list dir and add to cache
	_ = filepath.Walk(res.cacheDir, func(path string, info os.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}
		id, err := host.FileIDFromStringNoQuites(filepath.Base(path))
		id2 := id.StringNoQuotes()
		if filepath.Base(path) != id2 {
			return nil
		}
		if err != nil {
			return nil
		}

		res.lru.Put(FileID(id), int(info.Size()))
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
//todo ignore linux-vdso.1.so

func (c *FSCache) Open(fid host.FileID, elfRef *pfelf.Reference) *LazyTable {
	logtag := fmt.Sprintf("fid=%s elf=%s", fid.StringNoQuotes(), elfRef.FileName())
	//fmt.Printf("fscache open  %s %s\n", fid.StringNoQuotes(), elfRef.FileName())
	var err error
	var dst *os.File
	var src *os.File

	c.mu.Lock()
	defer c.mu.Unlock()
	_, _ = c.lru.Get(FileID(fid))
	tableFilePath := c.tableFilePath(fid)
	info, err := os.Stat(tableFilePath)
	if err == nil && info != nil {
		return &LazyTable{cache: c, fid: FileID(fid)}
	}

	o, ok := elfRef.ELFOpener.(pfelf.RootFSOpener)
	if !ok {
		return nil
	}

	elf, err := elfRef.GetELF()
	if err != nil {
		fmt.Printf("failed to open elf %s: %s\n", logtag, err.Error())
		return nil
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
				return nil
			}
			fmt.Printf("err open %s\n", err.Error())
			return nil
		}
	}

	defer src.Close()

	dst, err = os.Create(tableFilePath)
	if err != nil {
		fmt.Printf("err create %s %s %s %s\n", fid.StringNoQuotes(), tableFilePath, elfRef.FileName(), err.Error())
		return nil
	}
	defer dst.Close()

	t1 := time.Now()
	err = c.convertAsync(src, dst)

	if err != nil {
		fmt.Printf("%s convert took %s err : %v \n", logtag, time.Since(t1), err)
		_ = os.Remove(tableFilePath)
		return nil
	}

	sz := 0
	stat, _ := dst.Stat()
	if stat != nil {
		sz = int(stat.Size())
	}
	fmt.Printf("%s convert took %s size: %v , err : %v \n", logtag, time.Since(t1), sz, err)

	c.lru.Put(FileID(fid), sz)
	return &LazyTable{cache: c, fid: FileID(fid)}

}

func (c *FSCache) convertAsync(src *os.File, dst *os.File) error {
	job := convertJob{src: src, dst: dst, result: make(chan error)}
	c.jobs <- job
	return <-job.result
}

func (c *FSCache) convertSync(src *os.File, dst *os.File) error {
	return symb.FDToTable(src, nil, dst)
}

func (c *FSCache) tableFilePath(fid host.FileID) string {
	return filepath.Join(c.cacheDir, fid.StringNoQuotes())
}

type LazyTable struct {
	cache *FSCache
	fid   FileID
}

func (t LazyTable) Size() int {
	return 0
}

func (t LazyTable) Close() {

}

func (t LazyTable) Lookup(addr uint64, symbols []string) []string {
	return symbols[:0]
}
