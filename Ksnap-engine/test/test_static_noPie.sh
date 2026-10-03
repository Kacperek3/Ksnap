#!/bin/bash

set -uo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENGINE_DIR="$(dirname "$TEST_DIR")"
PROGRAMS_DIR="$ENGINE_DIR/test_programs"

KSNAP="$ENGINE_DIR/build/Ksnap"
PROGRAM="$PROGRAMS_DIR/counter_static_noPie"

DUMP_LOG="$TEST_DIR/logs.txt"
RESTORE_LOG="$TEST_DIR/restore_logs.txt"
RESTORE_ERR="$TEST_DIR/restore_err.txt"

VALUE_PATTERN='^[0-9]+[[:space:]]*$'

PID=""
RESTORE_PID=""
TTY_STATE="$(stty -g 2>/dev/null)"

fail() {
    echo -e "${RED}TEST FAILED: $1${NC}"
    exit 1
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

echo "Starting tests"

[ -x "$KSNAP" ] || fail "$KSNAP not found, run 'make' first"
[ -x "$PROGRAM" ] || fail "$PROGRAM not found"

sudo -v || fail "sudo authentication failed"

: >"$DUMP_LOG"
: >"$RESTORE_LOG"
: >"$RESTORE_ERR"

cd "$PROGRAMS_DIR" || fail "cannot enter $PROGRAMS_DIR"

"$PROGRAM" >>"$DUMP_LOG" &
PID=$!
sleep 5

kill -STOP "$PID" || fail "cannot stop process $PID"

LAST_VAL=$(tail -n 1 "$DUMP_LOG" | tr -d '[:space:]')
[[ "$LAST_VAL" =~ $VALUE_PATTERN ]] ||
    fail "no counter value in $DUMP_LOG (read '$LAST_VAL')"

echo "Making process dump $PID..."
sudo -n "$KSNAP" -m Dump -p "$PID"
DUMP_RC=$?
[ "$DUMP_RC" -eq 0 ] || fail "Ksnap -m Dump exited with $DUMP_RC"

kill -9 "$PID" 2>/dev/null
wait "$PID" 2>/dev/null
PID=""

echo "Dump made on value: $LAST_VAL"
echo "Restoring process..."

sudo -n "$KSNAP" -m Restore >"$RESTORE_LOG" 2>"$RESTORE_ERR" </dev/null &
RESTORE_PID=$!
sleep 3

RESTORED_PID="$(deepest_descendant "$RESTORE_PID")"
if [ "$RESTORED_PID" != "$RESTORE_PID" ]; then
    sudo -n kill -9 "$RESTORED_PID" 2>/dev/null
fi

wait "$RESTORE_PID"
RESTORE_RC=$?
RESTORE_PID=""
[ "$RESTORE_RC" -eq 0 ] || fail "Ksnap -m Restore exited with $RESTORE_RC"

FIRST_VAL=$(grep -m 1 -E "$VALUE_PATTERN" "$RESTORE_LOG" | tr -d '[:space:]')
VALUES_COUNT=$(grep -cE "$VALUE_PATTERN" "$RESTORE_LOG")
EXPECTED=$((LAST_VAL + 1))

if [ -z "$FIRST_VAL" ]; then
    echo "--- stderr of Ksnap -m Restore ---"
    cat "$RESTORE_ERR"
    fail "restored process printed nothing, expected $EXPECTED"
fi

[ "$FIRST_VAL" -eq "$EXPECTED" ] ||
    fail "restored process continued from $FIRST_VAL, expected $EXPECTED"

[ "$VALUES_COUNT" -ge 2 ] ||
    fail "restored process printed $VALUES_COUNT value(s), so it is not running"

echo -e "${GREEN}TEST PASSED: ($LAST_VAL -> $FIRST_VAL)!${NC}"
