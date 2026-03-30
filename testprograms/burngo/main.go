package main

import (
	"fmt"
	"runtime"
	"syscall"
)

func printStack() {
	pcs := make([]uintptr, 32)
	n := runtime.Callers(2, pcs)
	frames := runtime.CallersFrames(pcs[:n])
	for {
		f, more := frames.Next()
		fmt.Printf("  0x%x  %s\n", f.PC, f.Function)
		if !more {
			break
		}
	}
}

func main() {
	pcs := make([]uintptr, 32)
	n := runtime.Callers(0, pcs)
	frames := runtime.CallersFrames(pcs[:n])
	for {
		f, more := frames.Next()
		if f.Function == "runtime.goexit" {
			fmt.Printf("runtime.goexit entry=0x%x\n", f.Entry)
			break
		}
		if !more {
			break
		}
	}

	printStack()
	fmt.Println()

	rfd, _ := syscall.Open("/dev/urandom", syscall.O_RDONLY, 0)
	wfd, _ := syscall.Open("/dev/null", syscall.O_WRONLY, 0)
	buf := make([]byte, 4096)
	for {
		n, _ := syscall.Read(rfd, buf)
		if n > 0 {
			syscall.Write(wfd, buf[:n])
		}
	}
}
