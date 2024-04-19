TARGET := socket_redir

CC := clang
CFLAGS := -g -Wall -O2
LDLIBS := -lelf -lz

STRIP := llvm-strip
BPFTOOL := bpftool
STAT_LIBS := /usr/lib64/libbpf.a

.PHONY: all
all: $(TARGET)

.PHONY: clean
clean:
	$(RM) *.skel.h *.bpf.o $(TARGET)


$(TARGET): %: %.c %.skel.h
	$(CC) $(CFLAGS) $(filter %.c,$^) $(STAT_LIBS) $(LDLIBS) -o $@

%.bpf.o: %.bpf.c
	$(CC) $(CFLAGS) -c -target bpf $^ -o $@
	$(STRIP) -g $@

%.skel.h: %.bpf.o
	$(BPFTOOL) gen skeleton $< > $@
