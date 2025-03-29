CC = gcc
CLANG = clang
CFLAGS = -Wall -O2
BPF_CFLAGS = -O2 -target bpf
LIBS := -lbpf -lelf -lz

KERN_TARGET = reuseport_kern.o
KERN_SOURCE = reuseport_kern.c
USER_TARGET = user_test
USER_SOURCE = user_test.c

all: $(KERN_TARGET) $(USER_TARGET)

$(KERN_TARGET): $(KERN_SOURCE)
        $(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(USER_TARGET): $(USER_SOURCE)
        $(CC) $(CFLAGS) $^ -o $@ $(LIBS)

clean:
        rm -f $(KERN_TARGET) $(USER_TARGET)
