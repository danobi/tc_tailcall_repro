ARCH := $(shell uname -m | sed 's/x86_64/x86/')
CLANG_BPF_SYS_INCLUDES = $(shell clang -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

all: main.c prog.skel.h
	gcc -lbpf main.c

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

%.bpf.o: %.bpf.c vmlinux.h
	clang -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(CLANG_BPF_SYS_INCLUDES) -c $(filter %.c,$^) -o $@
	llvm-strip -g $@

%.skel.h: %.bpf.o
	bpftool gen skeleton $< > $@

.PHONY: clean
clean:
	rm -f a.out vmlinux.h *.skel.h *.bpf.o
