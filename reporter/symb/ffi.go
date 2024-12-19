package symb

/*
#cgo LDFLAGS: ${SRCDIR}/../../target/release/libsymblib_capi.a
#cgo CFLAGS: -g -Wall
#include "symblib.h"
#include <stdlib.h>
// inc-4

// Declare wrapper functions for linking.
SymblibStatus rangeVisitorWrapper(void* user_data, SymblibRange* range);
*/
import "C"
import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"os"
	"runtime"
	"unsafe"
)

func writeAligned(f *os.File, data []byte) error {
	if _, err := f.Write(data); err != nil {
		return err
	}

	// Align to 16 bytes
	currentPos, err := f.Seek(0, os.SEEK_CUR)
	if err != nil {
		return err
	}

	padding := (16 - (currentPos % 16)) % 16
	if padding > 0 {
		zeros := make([]byte, padding)
		if _, err := f.Write(zeros); err != nil {
			return err
		}
	}

	return nil
}

func symlibError(c C.SymblibStatus) error {
	switch c {
	case C.SymblibStatus(0):
		return fmt.Errorf("OK: not actually an error")
	case C.SymblibStatus(1):
		return fmt.Errorf("IO error")
	case C.SymblibStatus(2):
		return fmt.Errorf("IO error: file not found")
	case C.SymblibStatus(3):
		return fmt.Errorf("Object file reading error")
	case C.SymblibStatus(4):
		return fmt.Errorf("DWARF reading error")
	case C.SymblibStatus(5):
		return fmt.Errorf("Symbol conversion error")
	case C.SymblibStatus(6):
		return fmt.Errorf("Return pad extraction error")
	case C.SymblibStatus(7):
		return fmt.Errorf("Invalid UTF-8")
	case C.SymblibStatus(8):
		return fmt.Errorf("The channel was already closed in a previous call")
	default:
		return fmt.Errorf("unknown error code: %v", c)
	}
}

type rangeExtractor struct {
	v Visitor
}

//export rangeVisitorWrapper
func rangeVisitorWrapper(userData unsafe.Pointer, rangePtr *C.SymblibRange) C.SymblibStatus {
	e := (*rangeExtractor)(userData)
	elfVA := uint64(rangePtr.elf_va)
	length := uint32(rangePtr.length)
	function := C.GoString(rangePtr._func)
	e.v.VisitRange(elfVA, length, uint32(rangePtr.depth), function)

	return 0
}

type Visitor interface {
	VisitRange(va uint64, length uint32, depth uint32, function string)
}

func RangeExtractor(f *os.File, v Visitor) error {
	ctx := new(rangeExtractor)
	ctx.v = v
	var p runtime.Pinner
	p.Pin(ctx.v)
	defer p.Unpin()
	status := C.symblib_rangeextr(
		C.int(f.Fd()),
		C.int(-1),
		C.SymblibRangeVisitor(C.rangeVisitorWrapper),
		unsafe.Pointer(ctx),
	)
	if status != 0 {
		return symlibError(C.SymblibStatus(status))
	}
	return nil
}

func FDToTable(executable *os.File, dwarfSup *os.File, output *os.File) error {
	sb := newStringBuilder()
	rb := newRangesBuilder()
	rc := &rangeCollector{sb: sb, rb: rb}

	if err := RangeExtractor(executable, rc); err != nil {
		return err
	}
	rb.sort()

	err2 := write(output, rc)
	if err2 != nil {
		return err2
	}
	log.Debugf("converted %s -> %s : %d ranges, %d strings", executable.Name(), output.Name(), len(rb.entries), len(sb.unique))

	return nil
}
