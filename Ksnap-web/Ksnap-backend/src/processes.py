"""Process listing straight from /proc.

The engine reads /proc/<pid>/{maps,mem,exe} itself, so the panel stays on the
same source of truth instead of pulling in an external dependency.
"""

import os
import pwd
from pathlib import Path

PROC = Path("/proc")

STATE_NAMES = {
    "R": "running",
    "S": "sleeping",
    "D": "disk sleep",
    "T": "stopped",
    "t": "tracing stop",
    "Z": "zombie",
    "X": "dead",
    "I": "idle",
}


class ProcessError(Exception):
    """The requested pid cannot be used as a dump target."""


def _read(path):
    try:
        return path.read_text(errors="replace")
    except (OSError, PermissionError):
        return None


def _username(uid):
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def _parse_stat(raw):
    """Split /proc/<pid>/stat, whose second field may contain spaces."""
    open_paren = raw.find("(")
    close_paren = raw.rfind(")")
    if open_paren < 0 or close_paren < 0:
        return None, []
    comm = raw[open_paren + 1 : close_paren]
    rest = raw[close_paren + 2 :].split()
    return comm, rest


def read_process(pid, proc=PROC):
    """One process as a dict, or None when it is gone or not dumpable."""
    directory = proc / str(pid)

    stat_raw = _read(directory / "stat")
    if stat_raw is None:
        return None

    comm, fields = _parse_stat(stat_raw)
    if comm is None or len(fields) < 18:
        return None

    # fields are shifted by 3 - pid, comm and state are already consumed
    state = fields[0]
    threads = int(fields[17])

    cmdline_raw = _read(directory / "cmdline") or ""
    cmdline = " ".join(part for part in cmdline_raw.split("\x00") if part)

    # kernel threads own no address space, there is nothing to snapshot
    if not cmdline:
        return None

    uid = None
    rss_kb = 0
    status_raw = _read(directory / "status") or ""
    for line in status_raw.splitlines():
        if line.startswith("Uid:"):
            uid = int(line.split()[1])
        elif line.startswith("VmRSS:"):
            rss_kb = int(line.split()[1])

    try:
        stat_result = (directory).stat()
        uid = uid if uid is not None else stat_result.st_uid
    except OSError:
        uid = uid if uid is not None else 0

    return {
        "pid": int(pid),
        "name": comm,
        "cmdline": cmdline,
        "user": _username(uid),
        "state": STATE_NAMES.get(state, state),
        "threads": threads,
        "rss_kb": rss_kb,
        # the MVP engine handles single threaded processes only
        "supported": threads == 1,
    }


def list_processes(query=None, proc=PROC):
    """Every dumpable process, optionally filtered by pid or name."""
    query = (query or "").strip().lower()
    processes = []

    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        process = read_process(entry.name, proc=proc)
        if process is None:
            continue
        if query and query not in str(process["pid"]) and (
            query not in process["name"].lower()
            and query not in process["cmdline"].lower()
        ):
            continue
        processes.append(process)

    processes.sort(key=lambda item: item["pid"])
    return processes


def validate_pid(value, proc=PROC):
    """Return a pid that is safe to hand to the engine, or raise ProcessError."""
    try:
        pid = int(value)
    except (TypeError, ValueError):
        raise ProcessError("pid must be a number")

    if pid <= 1:
        raise ProcessError("pid %s cannot be snapshotted" % pid)
    if pid == os.getpid():
        raise ProcessError("the API cannot snapshot itself")
    if not (proc / str(pid)).is_dir():
        raise ProcessError("process %d does not exist" % pid)

    return pid
