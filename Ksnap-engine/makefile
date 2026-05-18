.PHONY: all clean test
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

test:
	test/./test.sh

clean:
	rm -rf build/*
