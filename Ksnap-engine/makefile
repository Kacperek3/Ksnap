.PHONY: all clean test test_programs
CC := gcc  # compiler used for Ksnap
CFLAGS := -g -Wall -Iinclude 
SRCS := $(wildcard src/*.c)
OBJS := $(SRCS:src/%.c=build/%.o)
DEPS := $(OBJS:.o=.d)

DEPFLAGS := -MMD -MP

TARGET := build/Ksnap

all: $(TARGET)


$(TARGET) : $(OBJS)
	$(CC) $(OBJS) -o $(TARGET)

build/%.o : src/%.c
	@mkdir -p build
	$(CC) $(CFLAGS) $(DEPFLAGS) -c $< -o $@

test_programs: test_programs/threads test_programs/fpu_rounding \
	test_programs/fpu_spin test_programs/counter_dynamic_pie \
	test_programs/fd_reader test_programs/file_counter

test_programs/threads: test_programs/threads.c
	$(CC) -pthread -O0 -g $< -o $@

# static and non-PIE like counter_static_noPie, the layout the restore handles
test_programs/fpu_rounding: test_programs/fpu_rounding.c
	$(CC) -static -no-pie -O0 -g $< -o $@ -lm

test_programs/counter_dynamic_pie: test_programs/counter_static_noPie.c
	$(CC) -fPIE -pie -O0 -g $< -o $@

test_programs/fpu_spin: test_programs/fpu_spin.c
	$(CC) -static -no-pie -O2 -mavx -g $< -o $@

test_programs/fd_reader: test_programs/fd_reader.c
	$(CC) -static -no-pie -O0 -g $< -o $@

test_programs/file_counter: test_programs/file_counter.c
	$(CC) -static -no-pie -O0 -g $< -o $@

test: test_programs
	test/./test_restore_validation.sh
	test/./test_static_noPie.sh
	test/./test_dynamic_pie.sh
	test/./test_dump_kill.sh
	test/./test_check.sh
	test/./test_fpu.sh
	test/./test_fds.sh

clean:
	rm -rf build/*

-include $(DEPS)
