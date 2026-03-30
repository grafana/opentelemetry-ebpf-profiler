// burngo is a CGO PIE Go program that burns CPU by calling read(0,..) through
// libc in a tight loop.  This gives the Go process libc frames which the eBPF
// profiler's Go interpreter will (incorrectly) symbolize using this binary's
// pclntab, poisoning the frame cache for unrelated C processes.
//
// Build (CGO + PIE are both required to get p_vaddr=0 so Go function
// ELF offsets overlap with libc offsets):
//
//	CGO_ENABLED=1 go build -buildmode=pie -o burngo .
//
// The program also prints its own ELF-space addresses so you can verify
// the collision with burnc's output.
package main

/*
#include <unistd.h>
*/
import "C"

import (
	"unsafe"
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// loadBias reads /proc/self/maps to find the bias for this binary.
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

	var buf [256]C.char
	iter := 0
	for {
		select {
		case <-ticker.C:
			printStack(bias)
		default:
			// read from stdin (run as: ./burngo < /dev/urandom)
			// This drives execution through libc's __syscall_cancel at a
			// predictable ELF offset, creating the frame the eBPF profiler
			// caches under a PID-agnostic key.
			C.read(0, unsafe.Pointer(&buf[0]), C.size_t(len(buf)))
			iter++
		}
	}
}
