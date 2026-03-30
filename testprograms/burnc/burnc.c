#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>

extern void trampoline(void);

void do_work(void) {
	int rfd = open("/dev/urandom", O_RDONLY);
	int wfd = open("/dev/null", O_WRONLY);
	char buf[4096];
	for (;;) {
		int n = read(rfd, buf, sizeof(buf));
		if (n > 0)
			write(wfd, buf, n);
	}
}

int main(void) {
	printf("trampoline at %p\n", (void *)trampoline);
	trampoline();
	return 0;
}
