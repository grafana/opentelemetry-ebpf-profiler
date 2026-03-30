/*
 * burnc burns CPU by calling read(0,...) through libc in a tight loop and
 * prints its own stack with ELF-space (bias-subtracted) addresses — the same
 * values the eBPF profiler stores as ef.Data().
 *
 * Build with frame-pointers so the eBPF profiler can unwind the stack:
 *
 *   gcc -fno-omit-frame-pointer -O1 -o burnc burnc.c -ldl
 *
 * Compare the printed ELF offsets against burngo's output.  Any matching
 * address in libc is a cache-pollution site: the Go interpreter will have
 * labelled that offset with a Go function name, which the C process will
 * then inherit from the frame cache.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Read /proc/self/maps to find the load base of a mapped file. */
static unsigned long map_base(const char *needle)
{
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return 0;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (!strstr(line, needle) || !strstr(line, " r-xp "))
            continue;
        unsigned long start;
        if (sscanf(line, "%lx-", &start) == 1) {
            fclose(f);
            return start;
        }
    }
    fclose(f);
    return 0;
}

static void print_stack(void)
{
    void  *frames[64];
    int    n = backtrace(frames, 64);
    char **syms = backtrace_symbols(frames, n);

    unsigned long libc_base = map_base("libc.so");

    printf("c stack (libc_base=0x%lx):\n", libc_base);
    for (int i = 0; i < n; i++) {
        unsigned long va = (unsigned long)frames[i];
        Dl_info info = {0};
        unsigned long elf = va;
        const char *lib = "?";
        if (dladdr(frames[i], &info) && info.dli_fbase) {
            elf = va - (unsigned long)info.dli_fbase;
            lib = info.dli_fname ? info.dli_fname : "?";
        }
        printf("  va=0x%012lx  elf=0x%06lx  [%s]\n", va, elf, lib);
    }
    if (syms) free(syms);
    fflush(stdout);
}

int main(void)
{
    print_stack();

    /* Run as: ./burnc < /dev/urandom
     * read() returns real data, keeping execution in libc's __syscall_cancel
     * long enough for the eBPF profiler to capture the frame. */
    char buf[256];
    unsigned long iter = 0;
    for (;;) {
        read(0, buf, sizeof(buf));
        iter++;
        if (iter % 1000000 == 0)
            print_stack();
    }
    return 0;
}
