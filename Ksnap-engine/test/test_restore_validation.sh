#!/bin/bash
#
# Restore has to refuse a damaged or hostile snapshot instead of trusting it.
#
# Two things are checked here, and neither needs root.
#
# 1. The header carries counts and lengths that index fixed size arrays, so a
#    file that lies about them used to walk past the end of
#    ksnap_dump_header_t. These cases are rejected by read_snapshot_metadata,
#    before the fork and before any ptrace call.
# 2. A restore that fails halfway must kill the process it was building. The
#    child is forked from Ksnap and traced as its own child, so this part needs
#    no privileges either.

set -uo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENGINE_DIR="$(dirname "$TEST_DIR")"
KSNAP="$ENGINE_DIR/build/Ksnap"
# ignores argv and stays alive for a while, so a process left behind is visible
VICTIM_SOURCE="$ENGINE_DIR/test_programs/counter_static_noPie"
VICTIM_NAME="ksnap-victim"

WORK_DIR="$(mktemp -d)"

fail() {
    echo -e "${RED}TEST FAILED: $1${NC}"
    exit 1
}

pass() {
    echo -e "${GREEN}  ok${NC} $1"
}

cleanup() {
    rm -rf "$WORK_DIR"
    return 0
}
trap cleanup EXIT

# Write a snapshot whose header says exactly what the caller asks for.
#
# The layout mirrors ksnap_dump_header_t in include/dump_format.h. If that
# struct changes, these cases stop proving what they claim and the format
# version has to be bumped anyway, so the duplication is deliberate.
write_snapshot() {
    local path="$1"
    shift
    python3 - "$path" "$@" <<'PY'
import struct
import sys

PATH_MAX = 4096
MAX_KERNEL_MAPS = 4
REGS = 27
PAGE = 4096
VMA_SIZE = 48  # sizeof(vma_descriptor_t), asserted in dump_format.h
XSTATE = 576  # KSNAP_XSTATE_MIN_SIZE, the smallest XSAVE area accepted

HEADER = (
    "<8sIIQQQQI%dsI" % PATH_MAX
    + "QQ32s" * MAX_KERNEL_MAPS
    + "%dQ" % REGS
    + "QII"
)

fields = {
    "magic": b"KSNAPDMP",
    "version": 3,
    "vma_count": 1,
    "vma_table_offset": struct.calcsize(HEADER),
    "path_pool_offset": struct.calcsize(HEADER) + VMA_SIZE,
    "path_pool_size": 0,
    "xstate_offset": struct.calcsize(HEADER) + VMA_SIZE,
    "xstate_size": XSTATE,
    "data_offset": struct.calcsize(HEADER) + VMA_SIZE + XSTATE,
    "exe_path": b"/bin/counter",
    # derived from exe_path unless a case overrides it on purpose
    "exe_path_len": None,
    "kernel_map_count": 0,
    # 1 writes a real descriptor for a mapping at an address mmap must refuse,
    # 0 writes filler, which is enough for the header only cases
    "vma": 0,
    # how many filler bytes to put behind the header
    "body": VMA_SIZE + XSTATE + PAGE,
}

for argument in sys.argv[2:]:
    key, value = argument.split("=", 1)
    if key not in fields:
        raise SystemExit("unknown field %s" % key)
    if key == "exe_path":
        fields[key] = value.encode()
    elif key == "magic":
        fields[key] = value.encode()
    else:
        fields[key] = int(value)

if fields["exe_path_len"] is None:
    fields["exe_path_len"] = len(fields["exe_path"])

header = struct.pack(
    HEADER,
    fields["magic"],
    fields["version"],
    fields["vma_count"],
    fields["vma_table_offset"],
    fields["path_pool_offset"],
    fields["path_pool_size"],
    fields["data_offset"],
    fields["exe_path_len"],
    fields["exe_path"],
    fields["kernel_map_count"],
    *([0, 0, b""] * MAX_KERNEL_MAPS),
    *([0] * REGS),
    fields["xstate_offset"],
    fields["xstate_size"],
    0,
)

if fields["vma"]:
    # start_address, size, file_offset, data_offset, prot, map_flags,
    # path_offset, path_len - vma_descriptor_t in include/dump_format.h.
    # 0x1000 is below vm.mmap_min_addr, so the injected mmap is refused.
    body = struct.pack(
        "<QQQQIIII",
        0x1000,
        PAGE,
        0,
        fields["data_offset"],
        0x7,
        0x22,
        0,
        0,
    ) + b"\0" * (XSTATE + PAGE)
else:
    body = b"\0" * fields["body"]

with open(sys.argv[1], "wb") as handle:
    handle.write(header)
    handle.write(body)
PY
}

# restore the named snapshot and assert it was refused with *expected* in the
# message, without a signal
refused_with() {
    local name="$1" expected="$2" what="$3"
    local output status

    output="$("$KSNAP" -m Restore -d "$WORK_DIR" -n "$name" 2>&1)"
    status=$?

    [ "$status" -ne 0 ] ||
        fail "$what was accepted: $output"
    # 128 and above means the engine died on a signal rather than refusing
    [ "$status" -lt 128 ] ||
        fail "$what killed the engine with signal $((status - 128)): $output"
    echo "$output" | grep -qi -- "$expected" ||
        fail "$what was refused, but not for the stated reason: $output"

    pass "$what is refused ($(echo "$output" | head -n 1))"
}

echo "Checking that a bad snapshot is refused"

[ -x "$KSNAP" ] || fail "$KSNAP not found, run 'make' first"
command -v python3 >/dev/null || fail "python3 is needed to craft the snapshots"

write_snapshot "$WORK_DIR/magic.ksnap" magic=NOTKSNAP
refused_with magic.ksnap "not a Ksnap snapshot" "a foreign file"

write_snapshot "$WORK_DIR/version.ksnap" version=99
refused_with version.ksnap "format version" "a snapshot from another format"

write_snapshot "$WORK_DIR/empty.ksnap" vma_count=0
refused_with empty.ksnap "no mapping" "a snapshot describing no mapping"

# the two counts that index fixed size arrays in the header
write_snapshot "$WORK_DIR/kmaps.ksnap" kernel_map_count=1000
refused_with kmaps.ksnap "kernel mappings" "a lie about the kernel mapping count"

write_snapshot "$WORK_DIR/kmaps5.ksnap" kernel_map_count=5
refused_with kmaps5.ksnap "kernel mappings" "one kernel mapping too many"

write_snapshot "$WORK_DIR/nopath.ksnap" exe_path_len=0
refused_with nopath.ksnap "executable path" "an empty executable path"

write_snapshot "$WORK_DIR/longpath.ksnap" exe_path_len=9999
refused_with longpath.ksnap "executable path" "an executable path longer than PATH_MAX"

# the XSAVE area is sized by the CPU, but never below the legacy region plus
# its header, and never large enough to be an allocation attack
write_snapshot "$WORK_DIR/noxstate.ksnap" xstate_size=0
refused_with noxstate.ksnap "xstate size" "a snapshot without the FPU/SSE/AVX state"

write_snapshot "$WORK_DIR/hugexstate.ksnap" xstate_size=4000000000
refused_with hugexstate.ksnap "xstate size" "an absurd FPU/SSE/AVX state size"

# the header promises an XSAVE area the file does not hold
write_snapshot "$WORK_DIR/cutxstate.ksnap" xstate_offset=999999999
refused_with cutxstate.ksnap "truncated" "an FPU/SSE/AVX state past the end of the file"

# nothing behind the header, so the table and the payload cannot be there
write_snapshot "$WORK_DIR/short.ksnap" body=0
refused_with short.ksnap "truncated" "a snapshot cut off after the header"

# a missing file is a different path, but it must not crash either
refused_with absent.ksnap "snapshot file" "a snapshot that is not there"

# ------------------------------------------------------------------------------
# A restore that fails after the fork must not release what it built
#
# The mapping below sits at 0x1000, under vm.mmap_min_addr, so the mmap injected
# into the child is refused and the restore fails with the child already
# exec'ed. Releasing it there would run the victim, and under sudo it would run
# as root.

[ -x "$VICTIM_SOURCE" ] || fail "$VICTIM_SOURCE not found"
cp "$VICTIM_SOURCE" "$WORK_DIR/$VICTIM_NAME"

write_snapshot "$WORK_DIR/badvma.ksnap" \
    "exe_path=$WORK_DIR/$VICTIM_NAME" vma=1

OUTPUT="$("$KSNAP" -m Restore -d "$WORK_DIR" -n badvma.ksnap 2>&1)"
STATUS=$?

[ "$STATUS" -ne 0 ] || fail "a restore that could not map anything reported success"
[ "$STATUS" -lt 128 ] ||
    fail "the engine died on signal $((STATUS - 128)): $OUTPUT"
echo "$OUTPUT" | grep -q "failed to restore mapping" ||
    fail "the failing mapping was not reported: $OUTPUT"
echo "$OUTPUT" | grep -q "killing the half restored process" ||
    fail "the half restored process was released instead of killed: $OUTPUT"
pass "a failed restore kills the process it was building"

sleep 0.5
LEFTOVER="$(pgrep -x "$VICTIM_NAME" | wc -l)"
[ "$LEFTOVER" -eq 0 ] ||
    fail "$LEFTOVER copy of $VICTIM_NAME survived the failed restore"
pass "nothing is left running afterwards"

echo -e "${GREEN}TEST PASSED${NC}"
