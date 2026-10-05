#!/bin/bash
#
# Dump a running counter, kill it, restore it and check that it continues from
# the right value with the same memory protections.
#
# Usage: test_static_noPie.sh [program]
#
# Without an argument the static non-PIE counter is used. test_dynamic_pie.sh
# passes a dynamically linked PIE build of the same counter.

set -uo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENGINE_DIR="$(dirname "$TEST_DIR")"
PROGRAMS_DIR="$ENGINE_DIR/test_programs"

KSNAP="$ENGINE_DIR/build/Ksnap"
PROGRAM="${1:-$PROGRAMS_DIR/counter_static_noPie}"

DUMP_LOG="$TEST_DIR/logs.txt"
RESTORE_LOG="$TEST_DIR/restore_logs.txt"
RESTORE_ERR="$TEST_DIR/restore_err.txt"
ORIGINAL_MAPS="$TEST_DIR/original_maps.txt"
RESTORED_MAPS="$TEST_DIR/restored_maps.txt"

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

echo "Starting tests on $(basename "$PROGRAM")"

[ -x "$KSNAP" ] || fail "$KSNAP not found, run 'make' first"
[ -x "$PROGRAM" ] || fail "$PROGRAM not found"

mkdir -p "$ENGINE_DIR/save" || fail "cannot create $ENGINE_DIR/save"

sudo -v || fail "sudo authentication failed"

: >"$DUMP_LOG"
: >"$RESTORE_LOG"
: >"$RESTORE_ERR"
: >"$ORIGINAL_MAPS"
: >"$RESTORED_MAPS"

cd "$PROGRAMS_DIR" || fail "cannot enter $PROGRAMS_DIR"

"$PROGRAM" >>"$DUMP_LOG" &
PID=$!
sleep 5

kill -STOP "$PID" || fail "cannot stop process $PID"

# the layout the restored process has to come back with, protections included
cat "/proc/$PID/maps" >"$ORIGINAL_MAPS" || fail "cannot read the maps of $PID"

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
    # the restored process runs as root, so its maps need root as well
    sudo -n cat "/proc/$RESTORED_PID/maps" >"$RESTORED_MAPS" 2>/dev/null
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

# Every mapping the engine copies has to come back with the protection it had.
# The restored areas are anonymous and neighbours with equal flags may merge,
# so an original range only has to lie inside one restored range with the same
# rwx bits. The kernel mappings, the unreadable and the shared ones are skipped,
# as the engine skips them, see classify_maps_line in src/maps.c.
[ -s "$RESTORED_MAPS" ] || fail "the maps of the restored process were not read"

WRONG_PROT="$(python3 - "$ORIGINAL_MAPS" "$RESTORED_MAPS" <<'PY'
import sys

KERNEL = {"[vdso]", "[vvar]", "[vvar_vclock]", "[vsyscall]"}


def parse(path):
    for line in open(path):
        fields = line.split(maxsplit=5)
        start, end = (int(value, 16) for value in fields[0].split("-"))
        name = fields[5].strip() if len(fields) > 5 else ""
        yield start, end, fields[1], name


restored = list(parse(sys.argv[2]))

for start, end, perms, name in parse(sys.argv[1]):
    if name in KERNEL or perms[0] != "r" or perms[3] != "p":
        continue
    match = [
        r_perms
        for r_start, r_end, r_perms, _ in restored
        if r_start <= start and end <= r_end
    ]
    if not match or match[0][:3] != perms[:3]:
        print(
            "%x-%x %s %s came back as %s"
            % (start, end, perms, name or "[anon]", match[0] if match else "nothing")
        )
PY
)"

[ -z "$WRONG_PROT" ] ||
    fail "protections were not restored:
$WRONG_PROT"

echo -e "${GREEN}TEST PASSED: ($LAST_VAL -> $FIRST_VAL), protections intact!${NC}"
