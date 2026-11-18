from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import time
from pathlib import Path

from .errors import NotFound


def digest(device: str, lines: list[str]) -> str:
    return hashlib.sha256(json.dumps([device, lines]).encode()).hexdigest()


class PlanStore:
    def __init__(self, directory: Path, clock=time.time):
        self.dir = Path(directory)
        self.clock = clock

    def create(self, device: str, lines: list[str], flags: list[dict], needs_approval: bool,
               mode: str, ttl_minutes: int, note: str = "") -> dict:
        plan = {
            "plan_id": "p_" + secrets.token_hex(4), "device": device, "lines": lines, "flags": flags,
            "needs_approval": needs_approval, "mode_at_plan": mode, "status": "pending", "note": note,
            "created": self.clock(), "expires": self.clock() + ttl_minutes * 60,
            "digest": digest(device, lines),
        }
        self.save(plan)
        return plan

    def path(self, plan_id: str) -> Path:
        if not re.fullmatch(r"p_[0-9a-f]{8}", plan_id or ""):
            raise NotFound(f"invalid plan id '{plan_id}'")
        return self.dir / f"{plan_id}.json"

    def load(self, plan_id: str) -> dict:
        p = self.path(plan_id)
        if not p.exists():
            raise NotFound(f"no such plan '{plan_id}'", hint="plans expire; create a new one with `plan`")
        return json.loads(p.read_text())

    def save(self, plan: dict) -> None:
        p = self.path(plan["plan_id"])
        p.write_text(json.dumps(plan, indent=2))
        try:
            os.chmod(p, 0o600)
        except OSError:
            pass
