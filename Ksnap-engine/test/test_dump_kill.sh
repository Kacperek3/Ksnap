#!/bin/bash
#
# Dump -k: the snapshot is written and the process ends with it.
#
# The counter is NOT stopped with SIGSTOP before the dump, unlike in
# test_static_noPie.sh. The engine kills it while it is still stopped by
# ptrace, so it never runs past the snapshot: the last value in its log has to
# be the very value the restored process continues from. A process that kept
# running for a moment after the dump would leave a gap or a repeated value.

set -uo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENGINE_DIR="$(dirname "$TEST_DIR")"
SAVE_DIR="$ENGINE_DIR/save"
SNAPSHOT="kill_after_dump.ksnap"

KSNAP="$ENGINE_DIR/build/Ksnap"
PROGRAM="$ENGINE_DIR/test_programs/counter_static_noPie"

DUMP_LOG="$TEST_DIR/kill_logs.txt"
RESTORE_LOG="$TEST_DIR/kill_restore_logs.txt"
RESTORE_ERR="$TEST_DIR/kill_restore_err.txt"

VALUE_PATTERN='^[0-9]+[[:space:]]*$'

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

echo "Checking Dump -k"

[ -x "$KSNAP" ] || fail "$KSNAP not found, run 'make' first"
[ -x "$PROGRAM" ] || fail "$PROGRAM not found"

# ------------------------------------------------------------------------------
# -k belongs to Dump only, the other modes refuse it instead of ignoring it

for mode in Restore Check; do
    OUTPUT="$("$KSNAP" -m "$mode" -k 2>&1)"
    STATUS=$?
    [ "$STATUS" -ne 0 ] || fail "-m $mode -k was accepted"
    echo "$OUTPUT" | grep -q "only be used with Dump" ||
        fail "-m $mode -k was refused for another reason: $OUTPUT"
    pass "-m $mode -k is refused"
done

# ------------------------------------------------------------------------------
# dump -k on a running process, then restore it

mkdir -p "$SAVE_DIR" || fail "cannot create $SAVE_DIR"
sudo -v || fail "sudo authentication failed"

: >"$DUMP_LOG"
: >"$RESTORE_LOG"
: >"$RESTORE_ERR"
sudo -n rm -f "$SAVE_DIR/$SNAPSHOT"

"$PROGRAM" >>"$DUMP_LOG" &
PID=$!
sleep 3

OUTPUT="$(sudo -n "$KSNAP" -m Dump -p "$PID" -d "$SAVE_DIR" -n "$SNAPSHOT" -k 2>&1)"
STATUS=$?
[ "$STATUS" -eq 0 ] || fail "Ksnap -m Dump -k exited with $STATUS: $OUTPUT"
echo "$OUTPUT" | grep -q "terminated after the snapshot" ||
    fail "the engine did not report the termination: $OUTPUT"

# the shell is the parent, so wait reports how the counter ended
wait "$PID"
EXIT_STATUS=$?
PID=""
[ "$EXIT_STATUS" -eq $((128 + 9)) ] ||
    fail "the counter ended with status $EXIT_STATUS, expected SIGKILL (137)"
pass "the process was killed by the dump"

[ -s "$SAVE_DIR/$SNAPSHOT" ] || fail "no snapshot at $SAVE_DIR/$SNAPSHOT"
pass "the snapshot was written before the process ended"

# the counter is dead, its log is final
LAST_VAL="$(grep -E "$VALUE_PATTERN" "$DUMP_LOG" | tail -n 1 | tr -d '[:space:]')"
[ -n "$LAST_VAL" ] || fail "the counter printed nothing before the dump"

sudo -n "$KSNAP" -m Restore -d "$SAVE_DIR" -n "$SNAPSHOT" \
    >"$RESTORE_LOG" 2>"$RESTORE_ERR" </dev/null &
RESTORE_PID=$!
sleep 3

RESTORED_PID="$(deepest_descendant "$RESTORE_PID")"
[ "$RESTORED_PID" != "$RESTORE_PID" ] && sudo -n kill -9 "$RESTORED_PID" 2>/dev/null

wait "$RESTORE_PID"
RESTORE_RC=$?
RESTORE_PID=""
if [ "$RESTORE_RC" -ne 0 ]; then
    cat "$RESTORE_ERR"
    fail "Ksnap -m Restore exited with $RESTORE_RC"
fi

FIRST_VAL="$(grep -m 1 -E "$VALUE_PATTERN" "$RESTORE_LOG" | tr -d '[:space:]')"
[ -n "$FIRST_VAL" ] || fail "the restored process printed nothing"
[ "$FIRST_VAL" -eq $((LAST_VAL + 1)) ] ||
    fail "restored from $FIRST_VAL, but the original stopped at $LAST_VAL"
pass "the restored process continues exactly where the killed one stopped ($LAST_VAL -> $FIRST_VAL)"

echo -e "${GREEN}TEST PASSED${NC}"
