.PHONY: all clean burngo burnc

all: burngo burnc

burngo:
	CGO_ENABLED=1 go build -buildmode=pie -ldflags="-linkmode=external" -o burngo/burngo ./burngo/

burnc: burngo
	$(eval GOADDR := $(shell nm burngo/burngo 2>/dev/null | awk '/t main.main$$/{print "0x"$$1}'))
	@echo "burngo main.main at $(GOADDR) — placing burnc burn_work there"
	gcc -fno-omit-frame-pointer -fpie -pie -O1 \
		-Wl,--section-start=.text.burn=$(GOADDR) \
		-o burnc/burnc burnc/burnc.c -ldl -rdynamic

clean:
	rm -f burngo/burngo burnc/burnc

run: all
	@echo "Run:  ./burngo/burngo < /dev/urandom &  ./burnc/burnc &"
	@echo "Then: sudo ../ebpf-profiler -collection-agent=<host>:11000 -disable-tls -off-cpu-threshold=1"
