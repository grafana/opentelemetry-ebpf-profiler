package cache

import (
	"errors"
	"fmt"
	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/reporter/symb"
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

	return res
}

// todo consider mvoe this to reporter ExecutableInfo cache?
func (c *FSCache) Open(fid host.FileID, elfRef *pfelf.Reference) *symb.Table {
	return nil
	logtag := fmt.Sprintf("fid=%s elf=%s", fid.StringNoQuotes(), elfRef.FileName())
	//fmt.Printf("fscache open  %s %s\n", fid.StringNoQuotes(), elfRef.FileName())
	var err error
	var dst *os.File
	var src *os.File

	var t *symb.Table
	c.mu.Lock()
	defer c.mu.Unlock()
	//todo ignore linux-vdso.1.so
	_, _ = c.lru.Get(FileID(fid))
	dst, err = os.Open(c.tableFilePath(fid))
	if err == nil {
		t, err = symb.OpenFile(dst)
		if err == nil {
			//fmt.Printf("%s open  sz %d\n", logtag, t.Size())
			return t
		} else {
			dst.Close()
			fmt.Printf("open failed %s %s\n", logtag, err.Error())
			return nil
		}
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

	dst, err = os.Create(c.tableFilePath(fid))
	if err != nil {
		fmt.Printf("err create %s %s %s %s\n", fid.StringNoQuotes(), c.tableFilePath(fid), elfRef.FileName(), err.Error())
		return nil
	}

	//t1 := time.Now()
	err = symb.FDToTable(src, nil, dst)
	stat, _ := dst.Stat()
	//fmt.Printf("%s convert took %s err : %v | %+v\n", logtag, time.Since(t1), err, stat)
	if err != nil || stat == nil {
		dst.Close()
		_ = os.Remove(c.tableFilePath(fid))
		fmt.Printf("err open %s\n", err.Error()) //todo use retry mechanism in eim ?
		return nil
	}

	c.lru.Put(FileID(fid), int(stat.Size()))
	t, err = symb.OpenFile(dst)
	if err != nil {
		fmt.Printf("err open %s\n", err.Error())
		return nil
	}
	//fmt.Printf("%s open  sz %d\n", logtag, t.Size())
	return t

}

func (c *FSCache) tableFilePath(fid host.FileID) string {
	return filepath.Join(c.cacheDir, fid.StringNoQuotes())
}
