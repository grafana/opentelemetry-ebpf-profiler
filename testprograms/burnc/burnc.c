/*
 * burnc burns CPU in a tight loop and prints its own stack with
 * ELF-space addresses.
 *
 * The burn_work function is placed at a specific ELF offset (via the
 * linker script) that matches a Go function in burngo's pclntab.  When
 * both run under the eBPF profiler, burnc's frame at that offset gets
 * the Go function name from the poisoned frame cache.
 *
 * Build:
 *   make -C testprograms burnc
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

    unsigned long base = map_base("burnc");

    printf("c stack (base=0x%lx):\n", base);
    for (int i = 0; i < n; i++) {
        unsigned long va  = (unsigned long)frames[i];
        unsigned long elf = base ? va - base : va;
        printf("  va=0x%012lx  elf=0x%06lx\n", va, elf);
    }
    fflush(stdout);
}

/* Padding to push burn_work into the Go pclntab range (>= 0x800).
 * The exact match is verified at build time by the Makefile. */
__attribute__((noinline, used))
static void pad1(void) { asm volatile (".fill 200, 1, 0xcc"); }
__attribute__((noinline, used))
static void pad2(void) { asm volatile (".fill 200, 1, 0xcc"); }

__attribute__((noinline, used))
int burn_work(void)
{
    volatile int x = 0;
    for (int i = 0; i < 1000; i++)
        x += i;
    return x;
}

int main(void)
{
    print_stack();
    printf("burn_work is at elf offset shown above\n\n");

    unsigned long iter = 0;
    volatile int sum = 0;
    for (;;) {
        sum += burn_work();
        iter++;
        if (iter % 5000000 == 0)
            print_stack();
    }
    return 0;
}
