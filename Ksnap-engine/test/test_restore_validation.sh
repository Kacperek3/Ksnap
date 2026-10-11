#!/bin/bash
#
# Restore has to refuse a damaged or hostile snapshot instead of trusting it.
#
# Three things are checked here, and none of them needs root.
#
# 1. The header carries counts and lengths that index fixed size arrays, so a
#    file that lies about them used to walk past the end of
#    ksnap_dump_header_t. These cases are rejected by read_snapshot_metadata,
#    before the fork and before any ptrace call.
# 2. The fd table names files the child opens before its exec, as root under
#    sudo, so it is held to the same standard by read_fd_table.
# 3. A restore that fails halfway must kill the process it was building. The
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
#
# fds=FD:FLAGS:DUP_OF:PATH,... writes an fd table and a path pool holding those
# paths. fd_path_offset and fd_path_len override the first entry.
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
FD_SIZE = 32  # sizeof(fd_descriptor_t), asserted in dump_format.h
XSTATE = 576  # KSNAP_XSTATE_MIN_SIZE, the smallest XSAVE area accepted

HEADER = (
    "<8sIIQQQQI%dsI" % PATH_MAX
    + "QQ32s" * MAX_KERNEL_MAPS
    + "%dQ" % REGS
    + "QII"
    + "QII"
)

overrides = {}
for argument in sys.argv[2:]:
    key, value = argument.split("=", 1)
    overrides[key] = value

# fd, flags, dup_of, path - one fd_descriptor_t each
fds = []
for spec in filter(None, overrides.pop("fds", "").split(",")):
    fd, flags, dup_of, path = spec.split(":", 3)
    fds.append([int(fd), int(flags), int(dup_of), path.encode()])

pool = b""
for entry in fds:
    entry.append(len(pool))  # path_offset
    entry.append(len(entry[3]))  # path_len
    pool += entry[3] + b"\0"

for key in ("fd_path_offset", "fd_path_len"):
    if key in overrides:
        fds[0][4 if key == "fd_path_offset" else 5] = int(overrides.pop(key))

HEADER_SIZE = struct.calcsize(HEADER)
fd_table_offset = HEADER_SIZE + VMA_SIZE
pool_offset = fd_table_offset + FD_SIZE * len(fds)
xstate_offset = pool_offset + len(pool)

fields = {
    "magic": b"KSNAPDMP",
    "version": 4,
    "vma_count": 1,
    "vma_table_offset": HEADER_SIZE,
    "fd_count": len(fds),
    "fd_table_offset": fd_table_offset,
    "path_pool_offset": pool_offset,
    "path_pool_size": len(pool),
    "xstate_offset": xstate_offset,
    "xstate_size": XSTATE,
    "data_offset": xstate_offset + XSTATE,
    "exe_path": b"/bin/counter",
    # derived from exe_path unless a case overrides it on purpose
    "exe_path_len": None,
    "kernel_map_count": 0,
    # 1 writes a real descriptor for a mapping at an address mmap must refuse,
    # 0 writes filler, which is enough for the header only cases
    "vma": 0,
    # PROT_* of that descriptor
    "prot": 0x7,
    # how many filler bytes to put behind the header, by default exactly what
    # the layout above needs
    "body": None,
}

for key, value in overrides.items():
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
    fields["fd_table_offset"],
    fields["fd_count"],
    0,
)

if fields["vma"]:
    # start_address, size, file_offset, data_offset, prot, map_flags,
    # path_offset, path_len - vma_descriptor_t in include/dump_format.h.
    # 0x1000 is below vm.mmap_min_addr, so the injected mmap is refused.
    vma = struct.pack(
        "<QQQQIIII",
        0x1000,
        PAGE,
        0,
        fields["data_offset"],
        fields["prot"],
        0x22,
        0,
        0,
    )
else:
    vma = b"\0" * VMA_SIZE

# fd, dup_of, flags, path_offset, path_len, reserved, position -
# fd_descriptor_t in include/dump_format.h
table = b"".join(
    struct.pack("<iiIIIIQ", fd, dup_of, flags, offset, length, 0, 0)
    for fd, flags, dup_of, _, offset, length in fds
)

if fields["body"] is None:
    body = vma + table + pool + b"\0" * (XSTATE + PAGE)
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

# mprotect would refuse it only after the fork, with the payload already in
write_snapshot "$WORK_DIR/badprot.ksnap" vma=1 prot=255
refused_with badprot.ksnap "unknown protection" "a mapping with an unknown protection"

# ------------------------------------------------------------------------------
# The fd table

# the table promises more entries than the file holds
write_snapshot "$WORK_DIR/fdcount.ksnap" fd_count=1000000
refused_with fdcount.ksnap "truncated" "an fd table past the end of the file"

write_snapshot "$WORK_DIR/fdpool.ksnap" "fds=3:0:-1:/etc/hostname" \
    path_pool_size=0
refused_with fdpool.ksnap "no path pool" "descriptors without a path pool"

write_snapshot "$WORK_DIR/fdstdio.ksnap" "fds=1:0:-1:/etc/hostname"
refused_with fdstdio.ksnap "stdio" "a descriptor over stdio"

write_snapshot "$WORK_DIR/fdorder.ksnap" \
    "fds=4:0:-1:/etc/hostname,3:0:-1:/etc/hostname"
refused_with fdorder.ksnap "ascending order" "descriptors out of order"

write_snapshot "$WORK_DIR/fdtwice.ksnap" \
    "fds=3:0:-1:/etc/hostname,3:0:-1:/etc/hostname"
refused_with fdtwice.ksnap "ascending order" "one descriptor number twice"

write_snapshot "$WORK_DIR/fdduplater.ksnap" \
    "fds=3:0:-1:/etc/hostname,4:0:5:/etc/hostname"
refused_with fdduplater.ksnap "share the open file" \
    "a dup of a descriptor that comes later"

write_snapshot "$WORK_DIR/fddupmissing.ksnap" \
    "fds=3:0:-1:/etc/hostname,5:0:4:/etc/hostname"
refused_with fddupmissing.ksnap "share the open file" \
    "a dup of a descriptor that is not in the table"

# O_TRUNC, the kernel strips it after open, so only a crafted file has it
write_snapshot "$WORK_DIR/fdtrunc.ksnap" "fds=3:$((0x201)):-1:/etc/hostname"
refused_with fdtrunc.ksnap "create or truncate" "a descriptor that would truncate"

# O_CREAT
write_snapshot "$WORK_DIR/fdcreat.ksnap" "fds=3:$((0x41)):-1:/etc/hostname"
refused_with fdcreat.ksnap "create or truncate" "a descriptor that would create"

write_snapshot "$WORK_DIR/fdoffset.ksnap" "fds=3:0:-1:/etc/hostname" \
    fd_path_offset=9999
refused_with fdoffset.ksnap "outside the path pool" "a path past the pool"

write_snapshot "$WORK_DIR/fdnolen.ksnap" "fds=3:0:-1:/etc/hostname" \
    fd_path_len=0
refused_with fdnolen.ksnap "outside the path pool" "an empty path"

# the pool holds '/etc/hostname\0', a length of 4 leaves no terminator after it
write_snapshot "$WORK_DIR/fdnonul.ksnap" "fds=3:0:-1:/etc/hostname" \
    fd_path_len=4
refused_with fdnonul.ksnap "malformed path" "a path that is not terminated"

# ------------------------------------------------------------------------------
# A file the snapshot names but that is gone ends the child before its exec
#
# The child reopens the files between the fork and the exec, so there is no
# program running yet that could be released or would have to be killed.

[ -x "$VICTIM_SOURCE" ] || fail "$VICTIM_SOURCE not found"
cp "$VICTIM_SOURCE" "$WORK_DIR/$VICTIM_NAME"

write_snapshot "$WORK_DIR/fdgone.ksnap" "exe_path=$WORK_DIR/$VICTIM_NAME" \
    "fds=3:0:-1:$WORK_DIR/no-such-file"

OUTPUT="$("$KSNAP" -m Restore -d "$WORK_DIR" -n fdgone.ksnap 2>&1)"
STATUS=$?

[ "$STATUS" -ne 0 ] || fail "a restore whose file is gone reported success"
[ "$STATUS" -lt 128 ] ||
    fail "the engine died on signal $((STATUS - 128)): $OUTPUT"
echo "$OUTPUT" | grep -q "cannot reopen descriptor 3" ||
    fail "the missing file was not named: $OUTPUT"
echo "$OUTPUT" | grep -q "did not stop for the restore" ||
    fail "the engine did not notice the child gave up: $OUTPUT"
pass "a missing file ends the restore before the exec"

sleep 0.5
[ "$(pgrep -x "$VICTIM_NAME" | wc -l)" -eq 0 ] ||
    fail "$VICTIM_NAME runs although its file was missing"
pass "nothing is left running afterwards"

# ------------------------------------------------------------------------------
# A restore that fails after the fork must not release what it built
#
# The mapping below sits at 0x1000, under vm.mmap_min_addr, so the mmap injected
# into the child is refused and the restore fails with the child already
# exec'ed. Releasing it there would run the victim, and under sudo it would run
# as root.

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
