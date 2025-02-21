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

	"github.com/sirupsen/logrus"
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

func NewTableFactory() TableFactory {
	return TableTableFactory{}
}

type Resolver struct {
	logger   *logrus.Entry
	f        TableFactory
	mutex    sync.Mutex
	cacheDir string
	lru      *LRUCache[libpf.FileID, int]
	jobs     chan convertJob
	tables   map[libpf.FileID]Table
	known    map[libpf.FileID]struct{}
	errored  map[libpf.FileID]struct{}
	enabled  bool
	shutdown chan struct{}
	wg       sync.WaitGroup
}

func (c *Resolver) Cleanup() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	for _, table := range c.tables {
		table.Close()
	}
	clear(c.tables)
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

func NewFSCache(impl TableFactory, opt Options) (*Resolver, error) {
	l := logrus.WithField("component", "irsymtab")
	l.WithFields(logrus.Fields{
		"enabled": opt.Enabled,
		"path":    opt.Path,
		"size":    opt.Size,
	}).Info()

	lru := New[libpf.FileID, int](opt.Size, func(_ libpf.FileID, value int) int {
		return value
	})

	shutdown := make(chan struct{})
	res := &Resolver{
		logger:   l,
		f:        impl,
		cacheDir: opt.Path,
		lru:      lru,
		jobs:     make(chan convertJob, 1),
		shutdown: shutdown,
		tables:   make(map[libpf.FileID]Table),
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
		l.WithFields(logrus.Fields{
			"file": filePath,
			"size": sz,
		}).Debug("symbcache evicting")
		_ = os.Remove(filePath)
		res.mutex.Lock()
		delete(res.known, id)
		res.mutex.Unlock()
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

	// Start monitoring goroutine
	res.wg.Add(1)
	go func() {
		defer res.wg.Done()
		i := 0
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-shutdown:
				return
			case <-ticker.C:
				l.WithField("size", lru.Size()).Info("fscache lru size")
				i++
				if i%10 == 0 {
					res.mutex.Lock()
					res.errored = make(map[libpf.FileID]struct{})
					res.mutex.Unlock()
				}
			}
		}
	}()

	res.wg.Add(1)
	go func() {
		defer res.wg.Done()
		convertLoop(res)
	}()

	return res, nil
}

func convertLoop(res *Resolver) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	for {
		select {
		case <-res.shutdown:
			for len(res.jobs) > 0 {
				job := <-res.jobs
				job.result <- res.convertSync(job.src, job.dst)
			}
			return
		case job := <-res.jobs:
			job.result <- res.convertSync(job.src, job.dst)
		}
	}
}

func (c *Resolver) Observe(fid libpf.FileID, elfRef *pfelf.Reference) {
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

	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.isKnown(fid) {
		return
	}
	pid := 0
	if pp, ok := elfRef.ELFOpener.(process.Process); ok {
		pid = int(pp.PID())
	}
	l := c.logger.WithFields(logrus.Fields{
		"fid": fid.StringNoQuotes(),
		"elf": elfRef.FileName(),
		"pid": pid,
	})
	t1 := time.Now()
	err := c.convert(l, fid, elfRef, o)
	if err != nil {
		l.WithError(err).Error("conversion failed")
		c.errored[fid] = struct{}{}
	} else {
		l.Debug("converted")
		c.known[fid] = struct{}{}
	}
	l.WithField("duration", time.Since(t1)).Debug("conversion completed")
}

func (c *Resolver) convert(
	l *logrus.Entry,
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
			l.WithError(err).Debug("open debug file")
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

func (c *Resolver) getElf(l *logrus.Entry, elfRef *pfelf.Reference) (*pfelf.File, error) {
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
	l.WithField("proc", fmt.Sprintf("%+v", p)).Debug("Get mappings")
	openELF, err := p.OpenELF(elfRef.FileName())
	if err != nil {
		l.WithError(err).Error("DEBUG ESRCH open elf")
		return nil, err
	}

	return openELF, err
}

func (c *Resolver) convertAsync(src, dst *os.File) error {
	job := convertJob{src: src, dst: dst, result: make(chan error)}
	c.jobs <- job
	return <-job.result
}

func (c *Resolver) convertSync(src, dst *os.File) error {
	return c.f.ConvertTable(src, dst)
}

func (c *Resolver) tableFilePath(fid libpf.FileID) string {
	return filepath.Join(c.cacheDir, fid.StringNoQuotes())
}

var errUnknwnFile = errors.New("unknown file")

func (c *Resolver) ResolveAddress(fid libpf.FileID, addr uint64) ([]string, error) {
	if !c.enabled {
		return nil, nil
	}
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if !c.isKnown(fid) {
		return nil, errUnknwnFile
	}
	table, ok := c.tables[fid]
	if ok {
		return table.Lookup(addr)
	}
	path := c.tableFilePath(fid)
	table, err := c.f.OpenTable(path)
	if err != nil {
		_ = os.Remove(path)
		return nil, err
	}
	c.tables[fid] = table
	return table.Lookup(addr)
}

func (c *Resolver) Close() error {
	c.mutex.Lock()
	if c.shutdown != nil {
		close(c.shutdown)
		c.shutdown = nil
	}
	c.mutex.Unlock()

	c.wg.Wait()

	c.mutex.Lock()
	defer c.mutex.Unlock()

	for _, table := range c.tables {
		table.Close()
	}
	clear(c.tables)
	return nil
}

func (c *Resolver) isKnown(fid libpf.FileID) bool {
	if _, ok := c.known[fid]; ok {
		return true
	}
	if _, ok := c.errored[fid]; ok {
		return true
	}
	return false
}
