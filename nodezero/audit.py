"""Append-only audit logging for every action the tool takes.

Every module invocation, scope check, and AI suggestion is written here as a
single JSON line. This is what turns "an AI ran some scans" into something a
client or compliance reviewer can actually read afterward: who/what ran,
against which target, when, and with what result.
"""

from __future__ import annotations

import datetime as _dt
import json
from pathlib import Path
from threading import Lock


class AuditLog:
    """A JSONL audit log, safe for concurrent writers within one process."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = Lock()

    def record(self, event: str, **fields) -> None:
        """Append one audit entry.

        Args:
            event: Short event name, e.g. "scope_check", "module_start",
                "module_result", "ai_suggestion".
            **fields: Arbitrary JSON-serializable context for the event.
        """
        entry = {
            "ts": _dt.datetime.utcnow().isoformat() + "Z",
            "event": event,
            **fields,
        }
        line = json.dumps(entry, default=str)
        with self._lock:
            with self.path.open("a") as f:
                f.write(line + "\n")

    def read_all(self) -> list[dict]:
        if not self.path.exists():
            return []
        with self.path.open() as f:
            return [json.loads(line) for line in f if line.strip()]
