"""In memory console feed shared by the API and the panel.

Entries are numbered, so the browser only asks for what it has not seen yet
(GET /api/logs?since=<seq>) instead of re-downloading the whole console.
"""

import threading
from collections import deque
from datetime import datetime, timezone

INFO = "info"
SUCCESS = "success"
ERROR = "error"
OUTPUT = "output"


class Logbook:
    def __init__(self, capacity):
        self._entries = deque(maxlen=capacity)
        self._lock = threading.Lock()
        self._next_seq = 1

    def append(self, message, level=INFO, source="api"):
        """Record one line and return the stored entry."""
        for line in str(message).splitlines() or [""]:
            with self._lock:
                entry = {
                    "seq": self._next_seq,
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "level": level,
                    "source": source,
                    "message": line,
                }
                self._next_seq += 1
                self._entries.append(entry)
        return entry

    def since(self, seq):
        """Entries newer than *seq*, plus the cursor to ask for next time."""
        with self._lock:
            entries = [entry for entry in self._entries if entry["seq"] > seq]
            cursor = self._next_seq - 1
        return entries, cursor

    def clear(self):
        with self._lock:
            self._entries.clear()
