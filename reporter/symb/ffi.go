package symb

/*
#cgo LDFLAGS: ${SRCDIR}/../../target/release/libsymblib_capi.a
#cgo CFLAGS: -g -Wall
#include "symblib.h"
#include <stdlib.h>
// inc-3
*/
import "C"
import (
	"fmt"
	"io"
	"os"
)

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

// todo test what happens in empty symbols case ?
// todo if gnu_debuglink is found, exe should be the file in gnu_debuglink
// if gnu_debuglink file has gnu_debugaltlink, then the the gnu_debugaltlink file should be passed as dwarf_sup
// otherwise just pass the executable, nil
func FDToTable(executable_or_debug_file *os.File, dwarf_sup *os.File, output *os.File) error {
	dwarf_sup_fd := C.int(-1)
	if dwarf_sup != nil {
		dwarf_sup_fd = C.int(dwarf_sup.Fd())
	}
	res := C.symblib_exe_fd_to_table(
		C.int(executable_or_debug_file.Fd()),
		dwarf_sup_fd,
		C.int(output.Fd()),
	)

	if res != 0 {
		return symlibError(C.SymblibStatus(res))
	}

	_, err := output.Seek(0, io.SeekStart)
	if err != nil {
		return symlibError(1)
	}
	return nil
}
