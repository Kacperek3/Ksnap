"""The folders the panel keeps snapshots in.

The default store (config.SNAPSHOT_DIR) is always there. Every other folder a
dump was written to is remembered in a small JSON file, so the panel can list,
restore and delete the snapshots in it later. Restore and delete only accept
folders from this list: the API never reaches into a folder it did not write
to itself.
"""

import json
import os
import tempfile
from pathlib import Path

import config

# the engine joins "<dir>/<name>" into PATH_MAX and keeps room for a name of
# NAME_MAX, see validate_dir in Ksnap-engine/include/parser.h
_PATH_MAX = 4096
_NAME_MAX = 255
MAX_LENGTH = _PATH_MAX - _NAME_MAX - 2


def _normalize(path):
    return Path(path).expanduser().resolve()


def validate(path):
    """Return a usable folder for a dump, creating it when it is missing.

    Raises ValueError with a message meant for the panel.
    """
    if not isinstance(path, str) or not path.strip():
        raise ValueError("folder must be a path")

    path = path.strip()
    if "\x00" in path:
        raise ValueError("folder contains a NUL character")
    if not Path(path).expanduser().is_absolute():
        raise ValueError("folder must be an absolute path")

    directory = _normalize(path)
    if len(str(directory)) > MAX_LENGTH:
        raise ValueError("folder path is longer than %d characters" % MAX_LENGTH)

    try:
        directory.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise ValueError("cannot create %s: %s" % (directory, error.strerror))
    if not directory.is_dir():
        raise ValueError("%s is not a folder" % directory)

    return directory


def _load():
    """Folders from the registry file, an unreadable file counts as empty."""
    try:
        with open(config.DIRECTORIES_FILE, encoding="utf-8") as handle:
            stored = json.load(handle)
    except (OSError, ValueError):
        return []

    if not isinstance(stored, list):
        return []
    return [item for item in stored if isinstance(item, str)]


def known():
    """The default store first, then every remembered folder that still exists."""
    default = _normalize(config.SNAPSHOT_DIR)
    folders = [default]

    for item in _load():
        folder = _normalize(item)
        if folder not in folders and folder.is_dir():
            folders.append(folder)

    return folders


def remember(directory):
    """Add *directory* to the registry, return False when it cannot be saved."""
    directory = _normalize(directory)
    if directory in known():
        return True

    stored = _load()
    stored.append(str(directory))

    registry = Path(config.DIRECTORIES_FILE)
    try:
        registry.parent.mkdir(parents=True, exist_ok=True)
        # written aside and moved over, a crash never leaves half a file
        handle, temporary = tempfile.mkstemp(dir=registry.parent, suffix=".tmp")
        with os.fdopen(handle, "w", encoding="utf-8") as output:
            json.dump(stored, output, indent=2)
        os.replace(temporary, registry)
    except OSError:
        return False

    return True


def require_known(path):
    """Resolve the folder of an existing snapshot, the default one when empty.

    Raises ValueError for a folder the panel never wrote to.
    """
    if path is None or path == "":
        return _normalize(config.SNAPSHOT_DIR)
    if not isinstance(path, str) or "\x00" in path:
        raise ValueError("folder must be a path")

    directory = _normalize(path)
    if directory not in known():
        raise ValueError("%s is not a snapshot folder of this panel" % directory)
    return directory
