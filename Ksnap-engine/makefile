.PHONY: all clean
CC := gcc  # compiler used for Ksync
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

clean:
	rm -rf build/*
