CC = clang
CFLAGS = -O2 -target bpf

TARGET = reuseport_kern.o
SOURCE = reuseport_kern.c

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET)
