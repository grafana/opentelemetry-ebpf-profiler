// burngo burns CPU by reading from stdin (run as: ./burngo < /dev/urandom)
// using Go's syscall.Read, which on a CGO-linked binary with external linker
// goes through libc's __syscall_cancel at a predictable ELF offset.
//
// Build (external linker gives p_vaddr=0 so Go function ELF offsets start
// near 0 and overlap with libc function offsets):
//
//	CGO_ENABLED=1 go build -buildmode=pie -ldflags="-linkmode=external" -o burngo .
//
// The program prints its own ELF-space addresses on startup so you can
// compare against burnc's output and verify the collision address.
package main

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// loadBias reads /proc/self/maps to find the load bias of this binary.
// For a PIE binary with ELF p_vaddr==0 the bias equals the first r-xp
// segment's runtime start address.
func loadBias() uintptr {
	exe, _ := os.Executable()
	f, err := os.Open("/proc/self/maps")
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.Contains(line, " r-xp ") || !strings.Contains(line, exe) {
			continue
		}
		parts := strings.SplitN(strings.Fields(line)[0], "-", 2)
		base, _ := strconv.ParseUint(parts[0], 16, 64)
		return uintptr(base)
	}
	return 0
}

func printStack(bias uintptr) {
	pcs := make([]uintptr, 32)
	n := runtime.Callers(2, pcs)
	frames := runtime.CallersFrames(pcs[:n])
	fmt.Printf("go stack (bias=0x%x):\n", bias)
	for {
		f, more := frames.Next()
		fmt.Printf("  va=0x%012x  elf=0x%06x  %s\n",
			f.PC, uintptr(f.PC)-bias, f.Function)
		if !more {
			break
		}
	}
	fmt.Println()
}

func main() {
	bias := loadBias()
	printStack(bias)

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	buf := make([]byte, 256)
	for {
		select {
		case <-ticker.C:
			printStack(bias)
		default:
			// syscall.Read goes through libc's __syscall_cancel because
			// the binary is linked against libc via the external linker.
			syscall.Read(0, buf)
		}
	}
}
