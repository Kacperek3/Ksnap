"""The only place that runs the Ksnap binary.

Dump is a short call that returns once the snapshot is written. Restore keeps
running for as long as the restored process lives (the engine waitpid()s on it
in src/restorer.c), so it is tracked as a session whose output is streamed into
the logbook - that output is the restored program's own stdout.
"""

import json
import os
import signal
import subprocess
import threading
from datetime import datetime, timezone

import config
import directories
import logbook as logbook_module
import snapshot as snapshot_module

SUDO = "/usr/bin/sudo"
KILL = "/usr/bin/kill"

logbook = logbook_module.Logbook(config.LOG_CAPACITY)


class EngineError(Exception):
    """The engine could not be started or refused the request."""


def _binary():
    binary = config.ENGINE_BINARY
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise EngineError(
            "engine binary not found at %s - run 'make' in Ksnap-engine" % binary
        )
    return str(binary)


def _command(argv):
    """Prefix the engine call with sudo when the API is not root itself."""
    if config.uses_sudo():
        return [SUDO, "-n", *argv]
    return list(argv)


def _snapshot_dir():
    directory = config.SNAPSHOT_DIR
    directory.mkdir(parents=True, exist_ok=True)
    return str(directory)


# what the engine prints on stderr, translated into something the panel can
# show. The raw output stays in the console either way.
_FAILURES = (
    ("no dumpable mapping found", "the process has no memory the engine can "
                                 "copy, it may have exited mid dump"),
    ("exe path is empty", "the executable of the process cannot be resolved, "
                          "kernel threads cannot be snapshotted"),
    ("unexpected end of memory", "the memory of the process changed or became "
                                 "unreadable while it was being copied"),
    ("kernel mismatch", "the snapshot was taken on a different kernel, its "
                        "vdso no longer fits"),
    ("has no [vdso]", "the restored process lacks a mapping the snapshot "
                      "needs, dump and restore must run on the same kernel"),
    ("two step move would be needed", "the vdso of the new process overlaps "
                                      "the address the snapshot needs"),
    ("Operation not permitted", "ptrace was refused, the engine needs root "
                                "and the process must not be traced already"),
    ("No such process", "the process exited before the engine could attach"),
)


def _explain_failure(returncode, output):
    if config.uses_sudo() and "password is required" in output:
        return (
            "sudo asked for a password. Add a NOPASSWD rule for the engine "
            "(see Ksnap-backend/docs/README.md) or run the API as root with "
            "KSNAP_SUDO=0."
        )
    for marker, explanation in _FAILURES:
        if marker in output:
            return explanation
    return "engine exited with code %d" % returncode


# 'Ksnap -m Check' answers with this when the process is simply not a usable
# target, which is an answer and not a failure of the tool
CHECK_EXIT_BLOCKED = 11


def check(pid=None):
    """What the engine says about *pid*, or about every process when None.

    Returns {pid: report}, where a report is one JSON object as documented in
    Ksnap-engine/docs/markdown/check_mode.md. The engine is the authority on
    what it can dump, so the panel asks instead of reimplementing the rules.
    """
    argv = [_binary(), "-m", "Check"]
    if pid is not None:
        argv += ["-p", str(pid)]

    try:
        completed = subprocess.run(
            _command(argv),
            capture_output=True,
            text=True,
            timeout=config.CHECK_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        raise EngineError(
            "the eligibility check timed out after %.0fs"
            % config.CHECK_TIMEOUT_SECONDS
        )
    except OSError as error:
        raise EngineError("cannot start the engine: %s" % error)

    if completed.returncode not in (0, CHECK_EXIT_BLOCKED):
        message = _explain_failure(completed.returncode, completed.stderr.strip())
        logbook.append(
            "Eligibility check failed: %s" % message,
            level=logbook_module.ERROR,
            source="check",
        )
        raise EngineError(message)

    reports = {}
    for line in completed.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            report = json.loads(line)
            reports[int(report["pid"])] = report
        except (ValueError, KeyError, TypeError):
            # one unreadable line must not cost the whole listing
            logbook.append(
                "unreadable check output: %s" % line[:120],
                level=logbook_module.ERROR,
                source="check",
            )

    return reports


def dump(pid, name, kill=False, directory=None):
    """Snapshot *pid* into <directory>/<name>, synchronously.

    *directory* is a folder already checked by directories.validate, the
    default store when it is None.

    With *kill* the engine ends the process once the snapshot is on disk
    ('-k'), and it does so while the process is still stopped, so nothing runs
    past the saved state. A failed dump leaves the process running.
    """
    name = snapshot_module.validate_name(name)
    directory = str(directory) if directory else _snapshot_dir()
    command = [_binary(), "-m", "Dump", "-p", str(pid), "-d", directory, "-n", name]
    if kill:
        command.append("-k")
    argv = _command(command)

    logbook.append(
        "Dump of pid %d into %s%s"
        % (pid, name, ", the process ends with it" if kill else ""),
        source="dump",
    )

    try:
        completed = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=config.DUMP_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        raise EngineError("dump timed out after %.0fs" % config.DUMP_TIMEOUT_SECONDS)
    except OSError as error:
        raise EngineError("cannot start the engine: %s" % error)

    output = (completed.stdout + completed.stderr).strip()
    if output:
        logbook.append(
            output,
            level=logbook_module.ERROR if completed.returncode else logbook_module.INFO,
            source="engine",
        )

    if completed.returncode != 0:
        message = _explain_failure(completed.returncode, output)
        logbook.append("Dump failed: %s" % message, level=logbook_module.ERROR,
                       source="dump")
        raise EngineError(message)

    logbook.append(
        "Snapshot %s written to %s" % (name, directory),
        level=logbook_module.SUCCESS,
        source="dump",
    )
    if not directories.remember(directory):
        logbook.append(
            "%s could not be remembered, its snapshots will not be listed"
            % directory,
            level=logbook_module.ERROR,
            source="dump",
        )

    header = snapshot_module.read_header(snapshot_module.resolve(directory, name))
    header["directory"] = directory
    return header


class RestoreSession:
    """One running 'Ksnap -m Restore' and the process it brought back."""

    def __init__(self, name, process):
        self.name = name
        self.process = process
        self.started_at = datetime.now(timezone.utc).isoformat()
        self.finished_at = None
        self.returncode = None

    def running(self):
        return self.process.poll() is None

    def describe(self):
        return {
            "snapshot": self.name,
            "engine_pid": self.process.pid,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "running": self.running(),
            "returncode": self.returncode,
        }


_session = None
_session_lock = threading.Lock()


def _stream_output(session):
    """Pump the engine and the restored program's output into the console."""
    for line in session.process.stdout:
        logbook.append(line.rstrip("\n"), level=logbook_module.OUTPUT,
                       source="restore")

    session.returncode = session.process.wait()
    session.finished_at = datetime.now(timezone.utc).isoformat()

    if session.returncode == 0:
        logbook.append(
            "Restored process from %s exited normally" % session.name,
            level=logbook_module.SUCCESS,
            source="restore",
        )
    else:
        logbook.append(
            "Restore of %s ended with code %d" % (session.name, session.returncode),
            level=logbook_module.ERROR,
            source="restore",
        )


def restore(name, directory=None):
    """Start a restore session, refusing to run two of them at once.

    *directory* is a folder already checked by directories.require_known, the
    default store when it is None.
    """
    name = snapshot_module.validate_name(name)
    directory = str(directory) if directory else _snapshot_dir()
    path = snapshot_module.resolve(directory, name)
    if not path.is_file():
        raise EngineError("snapshot %s does not exist" % name)

    global _session
    with _session_lock:
        if _session is not None and _session.running():
            raise EngineError(
                "a restored process is already running (snapshot %s), stop it "
                "first" % _session.name
            )

        argv = _command([_binary(), "-m", "Restore", "-d", directory, "-n", name])
        logbook.append("Restore of %s" % name, source="restore")

        try:
            process = subprocess.Popen(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                # own process group, so the whole restored tree can be stopped
                start_new_session=True,
            )
        except OSError as error:
            raise EngineError("cannot start the engine: %s" % error)

        _session = RestoreSession(name, process)
        threading.Thread(
            target=_stream_output, args=(_session,), daemon=True
        ).start()
        return _session.describe()


def _signal_group(pgid, number):
    """Signal the restored tree, through sudo when the engine runs as root."""
    if config.uses_sudo():
        subprocess.run(
            [SUDO, "-n", KILL, "-%d" % number, "--", "-%d" % pgid],
            capture_output=True,
            text=True,
        )
    else:
        os.killpg(pgid, number)


def stop():
    """Terminate the running restore session, if any."""
    with _session_lock:
        session = _session

    if session is None or not session.running():
        raise EngineError("no restored process is running")

    pgid = session.process.pid
    logbook.append("Stopping the restored process", source="restore")

    try:
        _signal_group(pgid, signal.SIGTERM)
        session.process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        _signal_group(pgid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError) as error:
        raise EngineError("cannot stop the restored process: %s" % error)

    return session.describe()


def session():
    """Current restore session, or None when nothing has been restored yet."""
    with _session_lock:
        return _session.describe() if _session is not None else None
