CC := gcc  # compiler used for Ksync
CFLAGS := -o  # flags (-g for debug info)
Files := src/main.c dump/dumper.c # our entry file

TARGET_FILE := build/Ksnap

run:
	$(CC) -g $(Files) $(CFLAGS) $(TARGET_FILE)

clean:
	rm -f build/*


