CC := gcc  # compiler used for Ksync
CFLAGS := -o #-g # flags (-g for debug info)
Files := src/main.c # our entry file

TARGET_FILE := build/Ksync

run:
	$(CC) $(Files) $(CFLAGS) $(TARGET_FILE)
	build/./Ksync

clean:
	rm -f build/*


