#!/bin/bash
#
# Open regular files survive a restore: their descriptor numbers, their
# offsets, an offset shared through dup(), O_APPEND and FD_CLOEXEC. A pipe the
# process holds is left behind without breaking the restore.
#
# Check and Dump have to agree on which descriptors travel, the same way they
# agree on snapshot_bytes: both decide through classify_fd in src/fds.c, so the
# dumpable_fds Check promises is asserted against the fd_count Dump writes.
#
# The program runs in its own directory and opens its files by relative paths,
# while the restore runs from /. The files can only come back through the
# absolute paths the dump read out of /proc.

set -uo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENGINE_DIR="$(dirname "$TEST_DIR")"
PROGRAMS_DIR="$ENGINE_DIR/test_programs"

KSNAP="$ENGINE_DIR/build/Ksnap"
PROGRAM="$PROGRAMS_DIR/fd_reader"

WORK_DIR="$(mktemp -d)"
SNAPSHOT_NAME="fds.ksnap"

DUMP_LOG="$TEST_DIR/fds_logs.txt"
DUMP_ERR="$TEST_DIR/fds_dump_err.txt"
RESTORE_LOG="$TEST_DIR/fds_restore_logs.txt"
RESTORE_ERR="$TEST_DIR/fds_restore_err.txt"

VALUE_PATTERN='^[0-9]+ cloexec='

PIDS=()
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
    local pid
    for pid in "${PIDS[@]:-}"; do
        [ -n "$pid" ] && kill -9 "$pid" 2>/dev/null
    done
    if [ -n "$RESTORE_PID" ]; then
        kill_descendants "$RESTORE_PID"
        sudo -n kill -TERM "$RESTORE_PID" 2>/dev/null
    fi
    [ -n "$TTY_STATE" ] && stty "$TTY_STATE" 2>/dev/null
    rm -rf "$WORK_DIR"
    return 0
}
trap cleanup EXIT

# one field out of one JSON line, see test_check.sh
field() {
    python3 -c "
import json, sys

try:
    value = json.loads(sys.stdin.read())
    for key in sys.argv[1].split('.'):
        value = value[int(key)] if key.isdigit() else value[key]
except (ValueError, LookupError, TypeError):
    value = ''
print(value)
" "$1"
}

# fd_count out of a snapshot header. It sits right after the xstate fields at
# the end of ksnap_dump_header_t, see include/dump_format.h.
snapshot_fd_count() {
    sudo -n chmod a+r "$1" 2>/dev/null
    python3 -c "
import struct, sys

HEADER_SIZE = 4592  # sizeof(ksnap_dump_header_t), asserted in dump_format.h
with open(sys.argv[1], 'rb') as handle:
    header = handle.read(HEADER_SIZE)
fd_table_offset, fd_count, _ = struct.unpack_from('<QII', header, HEADER_SIZE - 16)
print(fd_count)
" "$1"
}

# the descriptors of a process past stdio, one 'fd -> target' line each
fd_table() {
    sudo -n find "/proc/$1/fd" -mindepth 1 -printf '%f -> %l\n' |
        awk -F ' -> ' '$1 > 2' | sort -n
}

# Start fd_reader in WORK_DIR on *input* and *output* and leave its pid in
# START_PID once it has opened everything, see START_PID in test_check.sh for
# why this is not $(start ...)
START_PID=""
start_reader() {
    local input="$1" output="$2" log="$3" _
    (cd "$WORK_DIR" && exec "$PROGRAM" "$input" "$output") \
        >>"$log" 2>&1 </dev/null &
    START_PID=$!
    PIDS+=("$START_PID")

    # the banner is printed once every descriptor is open
    for _ in $(seq 1 50); do
        grep -q '^fd_reader pid:' "$log" 2>/dev/null && return 0
        sleep 0.1
    done
    cat "$log"
    fail "fd_reader did not start"
}

echo "Checking that open regular files survive a restore"

[ -x "$KSNAP" ] || fail "$KSNAP not found, run 'make' first"
[ -x "$PROGRAM" ] || fail "$PROGRAM not found, run 'make test_programs' first"
command -v python3 >/dev/null || fail "python3 is needed to read the reports"

sudo -v || fail "sudo authentication failed"

: >"$DUMP_LOG"
: >"$DUMP_ERR"
: >"$RESTORE_LOG"
: >"$RESTORE_ERR"

# far more records than the test ever reads
seq -f '%05g' 0 999 >"$WORK_DIR/input.txt"

start_reader input.txt output.txt "$DUMP_LOG"
PID="$START_PID"

# a few records in, so the offset is far from where a fresh open would start
for _ in $(seq 1 100); do
    [ "$(grep -cE "$VALUE_PATTERN" "$DUMP_LOG")" -ge 3 ] && break
    sleep 0.1
done

# ------------------------------------------------------------------------------
# 1. Check counts what the dump is going to carry

REPORT="$(sudo -n "$KSNAP" -m Check -p "$PID")"
[ "$(echo "$REPORT" | field dumpable)" = "True" ] ||
    fail "fd_reader was reported as not dumpable: $REPORT"
[ "$(echo "$REPORT" | field facts.open_fds)" = "6" ] ||
    fail "expected 6 descriptors past stdio: $REPORT"
[ "$(echo "$REPORT" | field facts.volatile_fds)" = "2" ] ||
    fail "expected the two ends of the pipe as volatile: $REPORT"
[ "$(echo "$REPORT" | field facts.dumpable_fds)" = "4" ] ||
    fail "expected 4 regular files to be dumpable: $REPORT"
pass "Check sees 4 regular files and 2 pipe ends"

# ------------------------------------------------------------------------------
# 2. dump

kill -STOP "$PID" || fail "cannot stop process $PID"

ORIGINAL_FDS="$(fd_table "$PID")"
LAST_LINE="$(grep -E "$VALUE_PATTERN" "$DUMP_LOG" | tail -n 1)"
LAST_VAL="${LAST_LINE%% *}"
[ "$LAST_LINE" = "$LAST_VAL cloexec=1" ] ||
    fail "fd_reader was not healthy before the dump: '$LAST_LINE'"

sudo -n "$KSNAP" -m Dump -p "$PID" -d "$WORK_DIR" -n "$SNAPSHOT_NAME" \
    2>"$DUMP_ERR" || {
    cat "$DUMP_ERR"
    fail "Ksnap -m Dump of fd_reader failed"
}

kill -9 "$PID" 2>/dev/null
wait "$PID" 2>/dev/null

[ "$(grep -c 'is not carried over' "$DUMP_ERR")" = "2" ] ||
    fail "the dump did not report the two pipe ends it leaves behind:
$(cat "$DUMP_ERR")"
pass "the dump names the two pipe ends it leaves behind"

FD_COUNT="$(snapshot_fd_count "$WORK_DIR/$SNAPSHOT_NAME")"
[ "$FD_COUNT" = "4" ] ||
    fail "Check promised 4 descriptors, the snapshot holds $FD_COUNT"
pass "the snapshot holds the 4 descriptors Check promised"

# ------------------------------------------------------------------------------
# 3. restore, from another working directory

(cd / && exec sudo -n "$KSNAP" -m Restore -d "$WORK_DIR" -n "$SNAPSHOT_NAME") \
    >"$RESTORE_LOG" 2>"$RESTORE_ERR" </dev/null &
RESTORE_PID=$!
sleep 4

RESTORED="$(deepest_descendant "$RESTORE_PID")"
RESTORED_FDS=""
if [ "$RESTORED" != "$RESTORE_PID" ]; then
    RESTORED_FDS="$(fd_table "$RESTORED")"
    sudo -n kill -9 "$RESTORED" 2>/dev/null
fi

wait "$RESTORE_PID"
STATUS=$?
RESTORE_PID=""

if [ "$STATUS" -ne 0 ]; then
    echo "--- stderr of Ksnap -m Restore ---"
    cat "$RESTORE_ERR"
    fail "Ksnap -m Restore exited with $STATUS"
fi

BROKEN="$(grep -m 1 BROKEN "$RESTORE_LOG")"
[ -z "$BROKEN" ] || fail "the restored process lost a descriptor: $BROKEN"

RESTORED_LINES="$(grep -E "$VALUE_PATTERN" "$RESTORE_LOG")"
FIRST_VAL="$(echo "$RESTORED_LINES" | head -n 1 | cut -d ' ' -f 1)"
[ -n "$FIRST_VAL" ] || {
    cat "$RESTORE_ERR"
    fail "the restored process printed nothing"
}
[ "$FIRST_VAL" -eq $((LAST_VAL + 1)) ] ||
    fail "reading continued at record $FIRST_VAL, expected $((LAST_VAL + 1))"
pass "reading continues at the saved offset ($LAST_VAL -> $FIRST_VAL)"

# every second record comes through the dup, so a repeat here means the two
# descriptors came back with offsets of their own
[ "$(echo "$RESTORED_LINES" | wc -l)" -ge 3 ] ||
    fail "the restored process printed too little to tell: $RESTORED_LINES"
echo "$RESTORED_LINES" |
    awk 'NR > 1 && $1 != previous + 1 { exit 1 } { previous = $1 }' ||
    fail "records repeat or skip after the restore:
$RESTORED_LINES"
pass "the dup still shares the offset of the descriptor it was made from"

WRONG="$(echo "$RESTORED_LINES" | grep -v ' cloexec=1$' | head -n 1)"
[ -z "$WRONG" ] || fail "FD_CLOEXEC did not come back: '$WRONG'"
pass "FD_CLOEXEC is set again after the exec"

# the original wrote up to LAST_VAL, the restored one appended from there
awk 'NR - 1 != $1 + 0 { exit 1 }' "$WORK_DIR/output.txt" ||
    fail "output.txt is not one unbroken sequence:
$(cat "$WORK_DIR/output.txt")"
[ "$(tail -n 1 "$WORK_DIR/output.txt")" -gt $((LAST_VAL + 1)) ] ||
    fail "the restored process appended nothing to output.txt"
pass "writes go on appending to the same output file"

EXPECTED_FDS="$(echo "$ORIGINAL_FDS" | grep -v ' -> pipe:')"
[ "$RESTORED_FDS" = "$EXPECTED_FDS" ] ||
    fail "the descriptor table did not come back as it was
--- expected ---
$EXPECTED_FDS
--- restored ---
$RESTORED_FDS"
pass "the same numbers point at the same files, and nothing else is open"

# ------------------------------------------------------------------------------
# 4. a file that is gone fails the restore before anything runs

rm -f "$WORK_DIR/input.txt"

OUTPUT="$(cd / && sudo -n "$KSNAP" -m Restore -d "$WORK_DIR" \
    -n "$SNAPSHOT_NAME" 2>&1 </dev/null)"
STATUS=$?

[ "$STATUS" -ne 0 ] || fail "a restore whose input file is gone succeeded"
[ "$STATUS" -lt 128 ] ||
    fail "the engine died on signal $((STATUS - 128)): $OUTPUT"
echo "$OUTPUT" | grep -q "cannot reopen descriptor 3" ||
    fail "the missing file was not named: $OUTPUT"

sleep 0.5
[ "$(pgrep -x fd_reader | wc -l)" -eq 0 ] ||
    fail "an fd_reader is still running after the failed restore"
pass "a missing file is refused before the program runs"

# ------------------------------------------------------------------------------
# 5. a deleted file is open, but nothing the restore could reopen

seq -f '%05g' 0 999 >"$WORK_DIR/doomed.txt"
start_reader doomed.txt doomed-output.txt "$WORK_DIR/doomed.log"
DOOMED_PID="$START_PID"
rm -f "$WORK_DIR/doomed.txt"

REPORT="$(sudo -n "$KSNAP" -m Check -p "$DOOMED_PID")"
[ "$(echo "$REPORT" | field facts.open_fds)" = "6" ] ||
    fail "a deleted file stopped counting as open: $REPORT"
[ "$(echo "$REPORT" | field facts.dumpable_fds)" = "1" ] ||
    fail "only the output file should still be dumpable: $REPORT"
pass "Check stops promising a file once it is deleted"

sudo -n "$KSNAP" -m Dump -p "$DOOMED_PID" -d "$WORK_DIR" -n doomed.ksnap \
    2>"$DUMP_ERR" || {
    cat "$DUMP_ERR"
    fail "Ksnap -m Dump of the process with a deleted file failed"
}

[ "$(grep -c 'is not carried over' "$DUMP_ERR")" = "5" ] ||
    fail "the dump should leave 3 deleted files and 2 pipe ends behind:
$(cat "$DUMP_ERR")"
FD_COUNT="$(snapshot_fd_count "$WORK_DIR/doomed.ksnap")"
[ "$FD_COUNT" = "1" ] ||
    fail "Check promised 1 descriptor, the snapshot holds $FD_COUNT"
pass "the dump leaves out exactly what Check did not promise"

echo -e "${GREEN}TEST PASSED${NC}"
