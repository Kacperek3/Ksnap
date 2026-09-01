"""The only place that runs the Ksnap binary.

Dump is a short call that returns once the snapshot is written. Restore keeps
running for as long as the restored process lives (the engine waitpid()s on it
in src/restorer.c), so it is tracked as a session whose output is streamed into
the logbook - that output is the restored program's own stdout.
"""

import os
import signal
import subprocess
import threading
from datetime import datetime, timezone

import config
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


def _explain_failure(returncode, output):
    if config.uses_sudo() and "password is required" in output:
        return (
            "sudo asked for a password. Add a NOPASSWD rule for the engine "
            "(see Ksnap-backend/docs/README.md) or run the API as root with "
            "KSNAP_SUDO=0."
        )
    return "engine exited with code %d" % returncode


def dump(pid, name):
    """Snapshot *pid* into <snapshot dir>/<name>, synchronously."""
    name = snapshot_module.validate_name(name)
    argv = _command(
        [_binary(), "-m", "Dump", "-p", str(pid), "-d", _snapshot_dir(), "-n", name]
    )

    logbook.append("Dump of pid %d into %s" % (pid, name), source="dump")

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
        "Snapshot %s written" % name, level=logbook_module.SUCCESS, source="dump"
    )
    return snapshot_module.read_header(snapshot_module.resolve(_snapshot_dir(), name))


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


def restore(name):
    """Start a restore session, refusing to run two of them at once."""
    name = snapshot_module.validate_name(name)
    path = snapshot_module.resolve(_snapshot_dir(), name)
    if not path.is_file():
        raise EngineError("snapshot %s does not exist" % name)

    global _session
    with _session_lock:
        if _session is not None and _session.running():
            raise EngineError(
                "a restored process is already running (snapshot %s), stop it "
                "first" % _session.name
            )

        argv = _command([_binary(), "-m", "Restore", "-d", _snapshot_dir(), "-n", name])
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
