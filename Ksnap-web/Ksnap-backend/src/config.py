"""Runtime configuration of the Ksnap intermediate layer.

Every value can be overridden with an environment variable so the API can be
pointed at another checkout or another snapshot store without touching code.
"""

import os
from pathlib import Path

# <repo>/Ksnap-web/Ksnap-backend/src/config.py -> <repo>
REPO_ROOT = Path(__file__).resolve().parents[3]


def _path_from_env(name, default):
    value = os.environ.get(name)
    return Path(value).expanduser().resolve() if value else default


ENGINE_BINARY = _path_from_env(
    "KSNAP_ENGINE", REPO_ROOT / "Ksnap-engine" / "build" / "Ksnap"
)
SNAPSHOT_DIR = _path_from_env(
    "KSNAP_SNAPSHOT_DIR", REPO_ROOT / "Ksnap-engine" / "save"
)
# every other folder a dump was written to, see directories.py
DIRECTORIES_FILE = _path_from_env(
    "KSNAP_DIRECTORIES_FILE", SNAPSHOT_DIR / "directories.json"
)
FRONTEND_DIR = _path_from_env(
    "KSNAP_FRONTEND_DIR", REPO_ROOT / "Ksnap-web" / "Ksnap-frontend" / "src"
)

# the engine needs root for ptrace and /proc/<pid>/mem
#   auto - call sudo only when the API itself is not root (default)
#   1    - always call 'sudo -n'
#   0    - never, the API is expected to run as root already
SUDO_MODE = os.environ.get("KSNAP_SUDO", "auto").strip().lower()

# a dump of a large process still finishes in well under a second
DUMP_TIMEOUT_SECONDS = float(os.environ.get("KSNAP_DUMP_TIMEOUT", "60"))

# the panel drives a root capable engine, so it stays on the loopback
HOST = os.environ.get("KSNAP_HOST", "127.0.0.1")
PORT = int(os.environ.get("KSNAP_PORT", "5000"))

LOG_CAPACITY = int(os.environ.get("KSNAP_LOG_CAPACITY", "2000"))

# 'Ksnap -m Check' reports on every process in /proc in one go, so this is a
# whole listing rather than a single process
CHECK_TIMEOUT_SECONDS = float(os.environ.get("KSNAP_CHECK_TIMEOUT", "15"))

# the engine tells the panel exactly how many payload bytes a snapshot would
# hold, and above this the panel calls it out. A big snapshot is a warning, not
# a refusal, which is why the threshold lives here and not in the engine.
MAX_SNAPSHOT_MB = int(os.environ.get("KSNAP_MAX_SNAPSHOT_MB", "512"))


def uses_sudo():
    """Answer whether engine calls have to be wrapped in 'sudo -n'."""
    if SUDO_MODE in ("0", "false", "no", "off"):
        return False
    if SUDO_MODE in ("1", "true", "yes", "on"):
        return True
    return os.geteuid() != 0


def describe():
    """Snapshot of the configuration shown in the panel header."""
    return {
        "engine_binary": str(ENGINE_BINARY),
        "engine_present": ENGINE_BINARY.is_file() and os.access(ENGINE_BINARY, os.X_OK),
        "snapshot_dir": str(SNAPSHOT_DIR),
        "sudo": uses_sudo(),
        "root": os.geteuid() == 0,
    }
