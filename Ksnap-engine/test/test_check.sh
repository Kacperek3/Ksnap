#!/bin/bash
#
# Check mode: does the engine report honestly what it can and cannot dump.
#
# The important case is the invariant at the end: the snapshot_bytes that Check
# promises has to equal what Dump actually writes. That is the only assertion
# that keeps the two modes from drifting apart, because both of them reach the
# answer through classify_maps_line in src/maps.c.

set -uo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENGINE_DIR="$(dirname "$TEST_DIR")"
PROGRAMS_DIR="$ENGINE_DIR/test_programs"

KSNAP="$ENGINE_DIR/build/Ksnap"
COUNTER="$PROGRAMS_DIR/counter_static_noPie"
THREADS="$PROGRAMS_DIR/threads"

SNAPSHOT_DIR="$(mktemp -d)"
SNAPSHOT_NAME="check-invariant.ksnap"

PIDS=()

fail() {
    echo -e "${RED}TEST FAILED: $1${NC}"
    exit 1
}

pass() {
    echo -e "${GREEN}  ok${NC} $1"
}

skip() {
    echo -e "${YELLOW}  skipped${NC} $1"
}

cleanup() {
    local pid
    for pid in "${PIDS[@]:-}"; do
        [ -n "$pid" ] && kill -9 "$pid" 2>/dev/null
    done
    rm -rf "$SNAPSHOT_DIR"
    return 0
}
trap cleanup EXIT

# Start a program in the background and leave its pid in START_PID.
#
# It reports through a variable rather than stdout on purpose: called as
# $(start ...) the whole function would run in a subshell and the PIDS it
# appends to, which cleanup kills, would be lost with that subshell.
START_PID=""
start() {
    setsid "$@" >/dev/null 2>&1 </dev/null &
    START_PID=$!
    PIDS+=("$START_PID")
    sleep 1
}

# one field out of one JSON line, without assuming the key order. A numeric
# step indexes a list, so 'reasons.0.code' reaches into the first reason.
#
# A path that does not resolve prints nothing instead of raising: the caller
# then fails its own assertion and prints the whole report, which says far more
# than a traceback would.
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

echo "Checking Check mode"

[ -x "$KSNAP" ] || fail "$KSNAP not found, run 'make' first"
[ -x "$COUNTER" ] || fail "$COUNTER not found"
[ -x "$THREADS" ] || fail "$THREADS not found, run 'make test_programs'"
command -v python3 >/dev/null || fail "python3 is needed to read the reports"

sudo -v || fail "sudo authentication failed"

# ---------------------------------------------------------------- 1. the green
# case, a single threaded static program is exactly what the engine handles

start "$COUNTER"
COUNTER_PID="$START_PID"
REPORT="$(sudo -n "$KSNAP" -m Check -p "$COUNTER_PID")"
RC=$?

[ "$RC" -eq 0 ] || fail "Check on the counter exited with $RC, expected 0"
[ "$(echo "$REPORT" | field dumpable)" = "True" ] ||
    fail "the counter was reported as not dumpable: $REPORT"
[ "$(echo "$REPORT" | field facts.ptrace_ok)" = "True" ] ||
    fail "the ptrace probe did not succeed as root: $REPORT"
[ "$(echo "$REPORT" | field facts.threads)" = "1" ] ||
    fail "wrong thread count in $REPORT"
pass "a single threaded static program is dumpable, exit 0"

# the counter has to survive the probe, the stop from PTRACE_INTERRUPT lasts
# only until the detach
kill -0 "$COUNTER_PID" 2>/dev/null ||
    fail "the ptrace probe left the process dead"
STATE="$(sudo -n "$KSNAP" -m Check -p "$COUNTER_PID" | field facts.state)"
[ "$STATE" != "T" ] ||
    fail "the ptrace probe left the process stopped"
pass "the probe leaves the process running"

# ------------------------------------------------------- 2. the real invariant
# what Check promises is what Dump writes

PROMISED="$(echo "$REPORT" | field facts.snapshot_bytes)"

sudo -n "$KSNAP" -m Dump -p "$COUNTER_PID" -d "$SNAPSHOT_DIR" \
    -n "$SNAPSHOT_NAME" ||
    fail "the dump of $COUNTER_PID failed"

SNAPSHOT="$SNAPSHOT_DIR/$SNAPSHOT_NAME"
sudo -n chmod a+r "$SNAPSHOT" 2>/dev/null

WRITTEN="$(python3 -c "
import os, struct, sys

path = sys.argv[1]
with open(path, 'rb') as handle:
    # magic[8], version, vma_count, vma_table_offset, path_pool_offset,
    # path_pool_size, data_offset - see include/dump_format.h
    header = struct.unpack('<8sIIQQQQ', handle.read(8 + 4 + 4 + 8 * 4))
data_offset = header[6]
print(os.path.getsize(path) - data_offset)
" "$SNAPSHOT")"

[ "$PROMISED" = "$WRITTEN" ] ||
    fail "Check promised $PROMISED payload bytes, Dump wrote $WRITTEN"
pass "snapshot_bytes matches the payload the dump wrote ($WRITTEN B)"

# ------------------------------------------------------ 3. multi threaded case

start "$THREADS"
THREADS_PID="$START_PID"
REPORT="$(sudo -n "$KSNAP" -m Check -p "$THREADS_PID")"
RC=$?

[ "$RC" -eq 11 ] || fail "Check on a multi threaded process exited with $RC, expected 11"
[ "$(echo "$REPORT" | field dumpable)" = "False" ] ||
    fail "a multi threaded process was reported as dumpable: $REPORT"
[ "$(echo "$REPORT" | field 'reasons.0.code')" = "multi_threaded" ] ||
    fail "wrong reason for a multi threaded process: $REPORT"
pass "a multi threaded process is refused with multi_threaded, exit 11"

# ------------------------------------------------------- 4. deleted executable

DELETED_COPY="$SNAPSHOT_DIR/counter-copy"
cp "$COUNTER" "$DELETED_COPY"
start "$DELETED_COPY"
DELETED_PID="$START_PID"
rm -f "$DELETED_COPY"

REPORT="$(sudo -n "$KSNAP" -m Check -p "$DELETED_PID")"
[ "$(echo "$REPORT" | field 'reasons.0.code')" = "exe_deleted" ] ||
    fail "a deleted executable was not reported: $REPORT"
pass "a process whose binary is gone is refused with exe_deleted"

# --------------------------------------------------------- 5. traced processes

if command -v strace >/dev/null; then
    # the counter is started *under* strace rather than attached to afterwards:
    # the tracer is then its parent, so there is no race with the attach and no
    # dependency on yama ptrace_scope
    setsid strace -o /dev/null "$COUNTER" >/dev/null 2>&1 </dev/null &
    STRACE_PID=$!
    PIDS+=("$STRACE_PID")

    # wait for the precondition instead of assuming a sleep is enough
    TRACED_PID=""
    for _ in $(seq 20); do
        TRACED_PID="$(pgrep -P "$STRACE_PID" 2>/dev/null | head -n 1)"
        if [ -n "$TRACED_PID" ] &&
            [ "$(awk '/TracerPid:/ {print $2}' "/proc/$TRACED_PID/status" \
                2>/dev/null)" != "0" ]; then
            break
        fi
        TRACED_PID=""
        sleep 0.2
    done

    if [ -z "$TRACED_PID" ]; then
        skip "strace never took the process, cannot test already_traced"
    else
        PIDS+=("$TRACED_PID")
        REPORT="$(sudo -n "$KSNAP" -m Check -p "$TRACED_PID")"
        CODE="$(echo "$REPORT" | field 'reasons.0.code')"
        [ "$CODE" = "already_traced" ] || [ "$CODE" = "ptrace_refused" ] ||
            fail "a traced process was not refused: $REPORT"
        pass "a process under another tracer is refused with $CODE"
    fi
else
    skip "no strace, cannot test the already_traced case"
fi

# ------------------------------------------------------------- 6. the whole /proc

SWEEP="$(sudo -n "$KSNAP" -m Check)"
RC=$?
[ "$RC" -eq 0 ] || fail "the sweep exited with $RC, expected 0"

echo "$SWEEP" | python3 -c "
import json, sys

lines = [line for line in sys.stdin.read().splitlines() if line]
for line in lines:
    json.loads(line)
print(len(lines))
" >/dev/null || fail "the sweep produced a line that is not valid JSON"

LINES="$(echo "$SWEEP" | grep -c '^{')"
PROCESSES="$(ls -d /proc/[0-9]* | wc -l)"
# processes come and go between the two counts, a tenth of slack is plenty
[ "$LINES" -gt $((PROCESSES - PROCESSES / 10)) ] ||
    fail "the sweep reported $LINES processes out of about $PROCESSES"
pass "the sweep reports every process as valid JSON ($LINES lines)"

echo -e "${GREEN}TEST PASSED${NC}"
