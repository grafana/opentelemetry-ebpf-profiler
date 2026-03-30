.PHONY: all clean burngo burnc

all: burngo burnc

burngo:
	go build -o burngo/burngo ./burngo/

burnc: burngo
	GOADDR=$$(nm burngo/burngo | awk '/T runtime.goexit.abi0$$/{printf "0x%x\n", strtonum("0x"$$1) - 4}') && \
	sed "s/PLACEHOLDER/$$GOADDR/" burnc/linker.ld > burnc/linker_gen.ld && \
	gcc -fno-omit-frame-pointer -no-pie -O1 \
		-T burnc/linker_gen.ld \
		-o burnc/burnc burnc/burnc.c burnc/trampoline.S && \
	echo "trampoline at 0x$$GOADDR = runtime.goexit"

clean:
	rm -f burngo/burngo burnc/burnc burnc/linker_gen.ld
