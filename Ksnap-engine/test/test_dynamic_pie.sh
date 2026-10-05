#!/bin/bash
#
# Dump and restore a dynamically linked PIE process.
#
# The static non-PIE counter loads at the same address in the original and in
# the fresh exec the restore starts from. Here nothing does: the original runs
# with ASLR, so its binary, ld.so, libc and stack sit at random addresses, while
# the restore execs with ADDR_NO_RANDOMIZE. Every area has to be recreated at
# the address from the snapshot, next to whatever the fresh exec mapped, and the
# vdso has to be moved to where the restored libc expects it.
#
# The dump, restore, counter and protection checks are those of
# test_static_noPie.sh, run on counter_dynamic_pie, a PIE build of the same
# source. This script only makes sure the case really is the dynamic one.

set -uo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENGINE_DIR="$(dirname "$TEST_DIR")"
PROGRAM="$ENGINE_DIR/test_programs/counter_dynamic_pie"

# written by test_static_noPie.sh, the maps of the original before the dump
ORIGINAL_MAPS="$TEST_DIR/original_maps.txt"

fail() {
    echo -e "${RED}TEST FAILED: $1${NC}"
    exit 1
}

pass() {
    echo -e "${GREEN}  ok${NC} $1"
}

[ -x "$PROGRAM" ] ||
    fail "$PROGRAM not found, run 'make test_programs' first"

# a toolchain that quietly builds a static or non-PIE binary would turn this
# into a second copy of the static test
readelf -h "$PROGRAM" | grep -q 'Type:[[:space:]]*DYN' ||
    fail "$(basename "$PROGRAM") is not a PIE executable"
readelf -l "$PROGRAM" | grep -q 'INTERP' ||
    fail "$(basename "$PROGRAM") is not dynamically linked"
pass "$(basename "$PROGRAM") is a dynamically linked PIE executable"

if [ "$(cat /proc/sys/kernel/randomize_va_space 2>/dev/null)" = "0" ]; then
    echo -e "${YELLOW}  note${NC} ASLR is off, the original loads at the same" \
        "addresses as the restore, so relocation is not exercised"
fi

"$TEST_DIR/test_static_noPie.sh" "$PROGRAM" || exit 1

# the original really ran through ld.so and libc, so their mappings were part of
# the snapshot that was just restored
grep -q 'ld-linux' "$ORIGINAL_MAPS" ||
    fail "the original process had no ld.so mapping"
grep -qE '/libc[.-]' "$ORIGINAL_MAPS" ||
    fail "the original process had no libc mapping"
pass "ld.so and libc were dumped and restored with the process"

echo -e "${GREEN}TEST PASSED${NC}"
