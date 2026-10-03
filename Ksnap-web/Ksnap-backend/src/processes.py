"""Process listing straight from /proc.

Only the fields the table shows are read here. Whether a process is a usable
dump target is not decided in this module and not in Python at all: the engine
answers that through 'Ksnap -m Check', and eligibility.py attaches its verdict
to these rows by pid.
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


def read_text(path):
    """File contents, or None when the file or the process is gone."""
    try:
        return path.read_text(errors="replace")
    except OSError:
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


def read_process(pid, proc=None):
    """One process as a dict, or None when it is gone or has no address space."""
    proc = proc or PROC
    directory = proc / str(pid)

    stat_raw = read_text(directory / "stat")
    if stat_raw is None:
        return None

    comm, fields = _parse_stat(stat_raw)
    if comm is None or len(fields) < 18:
        return None

    # fields are shifted by 3 - pid, comm and state are already consumed
    state = fields[0]
    threads = int(fields[17])

    cmdline_raw = read_text(directory / "cmdline") or ""
    arguments = [part for part in cmdline_raw.split("\x00") if part]

    # kernel threads own no address space, there is nothing to snapshot
    if not arguments:
        return None

    uid = None
    rss_kb = 0
    for line in (read_text(directory / "status") or "").splitlines():
        if line.startswith("Uid:"):
            uid = int(line.split()[1])
        elif line.startswith("VmRSS:"):
            rss_kb = int(line.split()[1])

    if uid is None:
        try:
            uid = directory.stat().st_uid
        except OSError:
            uid = 0

    return {
        "pid": int(pid),
        "name": comm,
        "cmdline": " ".join(arguments),
        "user": _username(uid),
        "state": STATE_NAMES.get(state, state),
        "threads": threads,
        "rss_kb": rss_kb,
    }


def _matches(process, query):
    """Whether the free text *query* hits the pid, the name or the command."""
    return (
        query in str(process["pid"])
        or query in process["name"].lower()
        or query in process["cmdline"].lower()
    )


def list_processes(query=None, proc=None):
    """Every process with an address space, plus the kernel thread count."""
    proc = proc or PROC
    query = (query or "").strip().lower()
    found = []
    kernel_threads = 0

    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        process = read_process(entry.name, proc=proc)
        if process is None:
            kernel_threads += 1
            continue
        if query and not _matches(process, query):
            continue
        found.append(process)

    found.sort(key=lambda item: item["pid"])
    return found, kernel_threads


def validate_pid(value, proc=None):
    """Return a pid that is safe to hand to the engine, or raise ProcessError."""
    proc = proc or PROC
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
