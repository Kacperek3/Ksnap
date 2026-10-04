#!/bin/bash

set -uo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENGINE_DIR="$(dirname "$TEST_DIR")"
PROGRAMS_DIR="$ENGINE_DIR/test_programs"
SAVE_DIR="$ENGINE_DIR/save"

KSNAP="$ENGINE_DIR/build/Ksnap"

DUMP_LOG="$TEST_DIR/fpu_logs.txt"
RESTORE_LOG="$TEST_DIR/fpu_restore_logs.txt"
RESTORE_ERR="$TEST_DIR/fpu_restore_err.txt"

# fpu_spin prints once per 2^26 iterations, see REPORT_EVERY in fpu_spin.c
SPIN_REPORT_EVERY=$((1 << 26))

PID=""
RESTORE_PID=""
TTY_STATE="$(stty -g 2>/dev/null)"

fail() {
    echo -e "${RED}TEST FAILED: $1${NC}"
    exit 1
}

pass() {
    echo -e "${GREEN}  ok${NC} $1"
}

deepest_descendant() {
    local pid="$1" child
    child="$(pgrep -P "$pid" 2>/dev/null | head -n 1)"
    if [ -n "$child" ]; then
        deepest_descendant "$child"
    else
        echo "$pid"
    fi
}

kill_descendants() {
    local pid="$1" child
    for child in $(pgrep -P "$pid" 2>/dev/null); do
        kill_descendants "$child"
        sudo -n kill -9 "$child" 2>/dev/null
    done
}

cleanup() {
    [ -n "$PID" ] && kill -9 "$PID" 2>/dev/null
    if [ -n "$RESTORE_PID" ]; then
        kill_descendants "$RESTORE_PID"
        sudo -n kill -TERM "$RESTORE_PID" 2>/dev/null
    fi
    [ -n "$TTY_STATE" ] && stty "$TTY_STATE" 2>/dev/null
    return 0
}
trap cleanup EXIT

# Run *program*, dump it once it has printed a line matching *pattern*, kill it
# and restore it. Afterwards LAST_LINE holds the last line written before the
# dump and RESTORE_LOG the output of the restored process.
dump_and_restore() {
    local program="$1" pattern="$2" snapshot="$3"
    local _

    : >"$DUMP_LOG"
    : >"$RESTORE_LOG"
    : >"$RESTORE_ERR"

    "$program" >>"$DUMP_LOG" &
    PID=$!

    # at least two lines, so the program is in its steady state
    for _ in $(seq 1 100); do
        [ "$(grep -cE "$pattern" "$DUMP_LOG")" -ge 2 ] && break
        sleep 0.1
    done

    kill -STOP "$PID" || fail "cannot stop process $PID"

    LAST_LINE="$(grep -E "$pattern" "$DUMP_LOG" | tail -n 1)"
    [ -n "$LAST_LINE" ] || fail "$program printed nothing usable before the dump"

    sudo -n "$KSNAP" -m Dump -p "$PID" -d "$SAVE_DIR" -n "$snapshot" ||
        fail "Ksnap -m Dump of $program failed"

    kill -9 "$PID" 2>/dev/null
    wait "$PID" 2>/dev/null
    PID=""

    sudo -n "$KSNAP" -m Restore -d "$SAVE_DIR" -n "$snapshot" \
        >"$RESTORE_LOG" 2>"$RESTORE_ERR" </dev/null &
    RESTORE_PID=$!
    sleep 3

    local restored
    restored="$(deepest_descendant "$RESTORE_PID")"
    [ "$restored" != "$RESTORE_PID" ] && sudo -n kill -9 "$restored" 2>/dev/null

    wait "$RESTORE_PID"
    local status=$?
    RESTORE_PID=""

    if [ "$status" -ne 0 ]; then
        echo "--- stderr of Ksnap -m Restore ---"
        cat "$RESTORE_ERR"
        fail "Ksnap -m Restore of $program exited with $status"
    fi
}

restored_lines() {
    grep -E '^[0-9]+ ' "$RESTORE_LOG"
}

echo "Checking that the FPU/SSE/AVX state survives a restore"

[ -x "$KSNAP" ] || fail "$KSNAP not found, run 'make' first"
for program in fpu_rounding fpu_spin; do
    [ -x "$PROGRAMS_DIR/$program" ] ||
        fail "$PROGRAMS_DIR/$program not found, run 'make test_programs' first"
done

mkdir -p "$SAVE_DIR" || fail "cannot create $SAVE_DIR"
sudo -v || fail "sudo authentication failed"

# ------------------------------------------------------------------------------
# A. the rounding mode, MXCSR and the x87 control word

echo "A. rounding mode (fpu_rounding)"

dump_and_restore "$PROGRAMS_DIR/fpu_rounding" '^[0-9]+ sse=' fpu_rounding.ksnap

[ "$LAST_LINE" = "${LAST_LINE%% *} sse=U x87=U" ] ||
    fail "fpu_rounding was not rounding upward before the dump: $LAST_LINE"

LAST_VAL="${LAST_LINE%% *}"
FIRST_LINE="$(restored_lines | head -n 1)"
[ -n "$FIRST_LINE" ] || {
    cat "$RESTORE_ERR"
    fail "restored fpu_rounding printed nothing"
}

FIRST_VAL="${FIRST_LINE%% *}"
[ "$FIRST_VAL" -eq $((LAST_VAL + 1)) ] ||
    fail "restored fpu_rounding continued from $FIRST_VAL, expected $((LAST_VAL + 1))"
[ "$(restored_lines | wc -l)" -ge 2 ] ||
    fail "restored fpu_rounding printed one line only, so it is not running"
pass "the counter continues ($LAST_VAL -> $FIRST_VAL)"

WRONG="$(restored_lines | grep -v ' sse=U x87=U$' | head -n 1)"
[ -z "$WRONG" ] ||
    fail "the rounding mode was lost on restore: '$WRONG', expected sse=U x87=U"
pass "MXCSR and the x87 control word still round upward"

# ------------------------------------------------------------------------------
# B. live ymm registers in the middle of a computation

echo "B. live vector registers (fpu_spin)"

if ! grep -qw avx /proc/cpuinfo; then
    echo -e "${YELLOW}  skipped${NC} this CPU has no AVX"
else
    dump_and_restore "$PROGRAMS_DIR/fpu_spin" '^[0-9]+ (ok|BROKEN)' \
        fpu_spin.ksnap

    [ "$LAST_LINE" = "${LAST_LINE%% *} ok" ] ||
        fail "fpu_spin was already broken before the dump: $LAST_LINE"

    LAST_VAL="${LAST_LINE%% *}"
    FIRST_LINE="$(restored_lines | head -n 1)"
    [ -n "$FIRST_LINE" ] || {
        cat "$RESTORE_ERR"
        fail "restored fpu_spin printed nothing"
    }

    FIRST_VAL="${FIRST_LINE%% *}"
    EXPECTED=$((LAST_VAL + SPIN_REPORT_EVERY))
    [ "$FIRST_VAL" -eq "$EXPECTED" ] ||
        fail "restored fpu_spin continued from $FIRST_VAL, expected $EXPECTED"
    [ "$(restored_lines | wc -l)" -ge 2 ] ||
        fail "restored fpu_spin printed one line only, so it is not running"
    pass "the iteration counter continues ($LAST_VAL -> $FIRST_VAL)"

    WRONG="$(restored_lines | grep -v ' ok$' | head -n 1)"
    [ -z "$WRONG" ] ||
        fail "the vector registers were lost on restore: '$WRONG'"
    pass "every lane of the ymm accumulator is intact"
fi

echo -e "${GREEN}TEST PASSED${NC}"
