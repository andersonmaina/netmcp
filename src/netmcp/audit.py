from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

from .redact import redact_obj


class Audit:
    """Append-only JSONL audit log. Everything is redacted before it hits disk."""

    def __init__(self, path: Path, clock=time.time):
        self.path = Path(path)
        self.clock = clock

    def log(self, event: str, **fields) -> None:
        rec = {"ts": datetime.fromtimestamp(self.clock(), timezone.utc).isoformat(), "event": event}
        rec.update(redact_obj(fields))
        new = not self.path.exists()
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, default=str) + "\n")
        if new:
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass
