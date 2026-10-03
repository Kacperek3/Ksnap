.PHONY: all clean test test_programs
CC := gcc  # compiler used for Ksnap
CFLAGS := -g -Wall -Iinclude # flags (-g for debug info)
SRCS := $(wildcard src/*.c)
OBJS := $(SRCS:src/%.c=build/%.o)

TARGET := build/Ksnap

all: $(TARGET)


$(TARGET) : $(OBJS)
	$(CC) $(OBJS) -o $(TARGET)

build/%.o : src/%.c
	@mkdir -p build
	$(CC) $(CFLAGS) -c $< -o $@

# the counter binaries are committed on purpose, the restore test depends on
# their exact layout, so only the helpers that are not a dump target are built
# here
test_programs: test_programs/threads

test_programs/threads: test_programs/threads.c
	$(CC) -pthread -O0 -g $< -o $@

test: test_programs
	test/./test_static_noPie.sh
	test/./test_check.sh

clean:
	rm -rf build/*
