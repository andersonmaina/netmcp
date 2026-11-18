from __future__ import annotations

import os
from pathlib import Path


class Home:
    """Where netmcp keeps its config and state. Default: ~/.netmcp (override: NETMCP_HOME)."""

    def __init__(self, root: str | Path | None = None):
        self.root = Path(root or os.environ.get("NETMCP_HOME") or Path.home() / ".netmcp")
        self.inventory_path = self.root / "inventory.yaml"
        self.policy_path = self.root / "policy.yaml"
        self.state = self.root / "state"
        self.plans_dir = self.state / "plans"
        self.backups_dir = self.state / "backups"
        self.audit_path = self.state / "audit.jsonl"

    def ensure(self) -> None:
        for d in (self.root, self.state, self.plans_dir, self.backups_dir):
            d.mkdir(parents=True, exist_ok=True)
            try:
                d.chmod(0o700)
            except OSError:
                pass
