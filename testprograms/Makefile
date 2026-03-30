.PHONY: all clean burngo burnc

all: burngo burnc

# CGO + PIE are both required:
#   CGO  - so the Go process calls through libc, giving it libc frames
#   PIE  - so Go function ELF offsets start near 0, overlapping with libc offsets
#
# On this system libc's __syscall_cancel lands at ELF offset ~0x7a970, which
# coincides with sync.(*poolDequeue).popHead in the burngo binary.
burngo:
	CGO_ENABLED=1 go build -buildmode=pie -o burngo/burngo ./burngo/

# -fno-omit-frame-pointer lets the eBPF profiler unwind the C stack correctly.
burnc:
	gcc -fno-omit-frame-pointer -O1 -o burnc/burnc burnc/burnc.c -ldl

clean:
	rm -f burngo/burngo burnc/burnc

# Run both programs feeding /dev/urandom as stdin so read() keeps exercising
# libc's __syscall_cancel, then start the eBPF profiler.
# Expected result: the C process (burnc) shows Go function names
# (e.g. sync.(*poolDequeue).popHead) in its flamegraph.
run: all
	./burngo/burngo < /dev/urandom &
	./burnc/burnc   < /dev/urandom &
	@echo "burngo PID=$$!  burnc started"
	@echo "Now start the eBPF profiler:"
	@echo "  sudo ../ebpf-profiler -collection-agent=<host>:11000 -disable-tls -off-cpu-threshold=1"
