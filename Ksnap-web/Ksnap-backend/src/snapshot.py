"""Reading of the .ksnap files produced by the engine.

The on disk layout is defined in Ksnap-engine/include/dump_format.h. Only the
header is parsed here - it already carries everything the panel shows, so a
multi megabyte payload never has to be read.
"""

import re
import struct
from datetime import datetime, timezone
from pathlib import Path

MAGIC = b"KSNAPDMP"
FORMAT_VERSION = 2

MAX_KERNEL_MAPS = 4
KERNEL_MAP_NAME_LEN = 32
PATH_MAX = 4096

# ksnap_dump_header_t, x86_64 layout:
#   magic[8], version, vma_count, vma_table_offset, path_pool_offset,
#   path_pool_size, data_offset, exe_path_len, exe_path[PATH_MAX],
#   kernel_map_count, kernel_maps[4], regs
_KERNEL_MAP_FORMAT = "QQ32s"
_REGS_COUNT = 27  # struct user_regs_struct on x86_64
HEADER_FORMAT = (
    "<8sIIQQQQI%dsI" % PATH_MAX
    + _KERNEL_MAP_FORMAT * MAX_KERNEL_MAPS
    + "%dQ" % _REGS_COUNT
)
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

# indexes inside struct user_regs_struct
_RIP = 16
_RSP = 19

NAME_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
SUFFIX = ".ksnap"


class SnapshotError(Exception):
    """A file in the snapshot directory is not a usable snapshot."""


def validate_name(name):
    """Return a safe snapshot file name or raise ValueError.

    The name reaches the engine as '-n', so anything able to escape the
    snapshot directory has to be refused here.
    """
    if not isinstance(name, str):
        raise ValueError("snapshot name must be a string")

    name = name.strip()
    if not NAME_PATTERN.match(name):
        raise ValueError(
            "snapshot name may only contain letters, digits, dot, dash and "
            "underscore (max 64 characters)"
        )
    if name in (".", ".."):
        raise ValueError("invalid snapshot name")
    if not name.endswith(SUFFIX):
        name += SUFFIX
    return name


def resolve(directory, name):
    """Map a validated name onto a path that provably stays in *directory*."""
    directory = Path(directory).resolve()
    path = (directory / validate_name(name)).resolve()
    if path.parent != directory:
        raise ValueError("snapshot name escapes the snapshot directory")
    return path


def _decode(raw):
    return raw.split(b"\x00", 1)[0].decode("utf-8", "replace")


def read_header(path):
    """Parse one snapshot file into a plain dict."""
    path = Path(path)
    with path.open("rb") as handle:
        raw = handle.read(HEADER_SIZE)

    if len(raw) < HEADER_SIZE:
        raise SnapshotError("file is too short to hold a snapshot header")

    fields = struct.unpack(HEADER_FORMAT, raw)
    magic = fields[0]
    if magic != MAGIC:
        raise SnapshotError("not a Ksnap snapshot")

    version = fields[1]
    if version != FORMAT_VERSION:
        raise SnapshotError(
            "snapshot format version %d, this panel understands %d"
            % (version, FORMAT_VERSION)
        )

    exe_path_len = fields[7]
    kernel_map_count = fields[9]
    kernel_maps = []
    for index in range(min(kernel_map_count, MAX_KERNEL_MAPS)):
        start, size, name = fields[10 + index * 3 : 13 + index * 3]
        kernel_maps.append(
            {
                "name": _decode(name),
                "start_address": "0x%x" % start,
                "size": size,
            }
        )

    regs = fields[10 + MAX_KERNEL_MAPS * 3 :]
    stat = path.stat()

    return {
        "name": path.name,
        "size": stat.st_size,
        "created_at": datetime.fromtimestamp(
            stat.st_mtime, tz=timezone.utc
        ).isoformat(),
        "version": version,
        "vma_count": fields[2],
        "exe_path": _decode(fields[8][:exe_path_len]),
        "kernel_maps": kernel_maps,
        "rip": "0x%x" % regs[_RIP],
        "rsp": "0x%x" % regs[_RSP],
    }


def list_snapshots(directory):
    """All readable snapshots in *directory*, newest first.

    Unreadable or foreign files are reported with an 'error' field instead of
    being hidden - the user should see why a file in the store is unusable.
    """
    directory = Path(directory)
    if not directory.is_dir():
        return []

    snapshots = []
    for path in sorted(directory.glob("*" + SUFFIX)):
        try:
            snapshots.append(read_header(path))
        except (SnapshotError, OSError, struct.error) as error:
            stat = path.stat() if path.exists() else None
            snapshots.append(
                {
                    "name": path.name,
                    "size": stat.st_size if stat else 0,
                    "created_at": datetime.fromtimestamp(
                        stat.st_mtime, tz=timezone.utc
                    ).isoformat()
                    if stat
                    else None,
                    "error": str(error),
                }
            )

    snapshots.sort(key=lambda item: item.get("created_at") or "", reverse=True)
    return snapshots


def delete(directory, name):
    """Remove one snapshot, raising FileNotFoundError when it is not there."""
    path = resolve(directory, name)
    path.unlink()
