from __future__ import annotations

import re

from ..errors import DeviceError


class Driver:
    family = ""
    heartbeat_cmd = ""
    error_re: re.Pattern | None = None

    def __init__(self, device):
        self.device = device

    def normalize_read(self, cmd: str) -> str:
        return cmd.strip()

    def get_config(self, conn) -> str:
        raise NotImplementedError

    def show(self, conn, cmd: str, parse: bool = True):
        raise NotImplementedError

    def arm_rollback(self, conn, minutes: int) -> dict:
        """Arm a dead-man's switch on the device. Must raise DeviceError if it can't be confirmed armed."""
        raise NotImplementedError

    def disarm_rollback(self, conn, token: dict) -> None:
        raise NotImplementedError

    def persist(self, conn) -> bool:
        return False

    def send_lines(self, conn, lines: list[str]) -> str:
        return conn.send_config_set(lines)

    def apply(self, conn, lines: list[str]) -> str:
        out = self.send_lines(conn, lines)
        m = self.error_re.search(out) if self.error_re else None
        if m:
            raise DeviceError(f"device rejected a command: {m.group(0).strip()[:200]}")
        return out

    def heartbeat(self, conn) -> str:
        out = conn.send_command(self.heartbeat_cmd)
        if not out or not out.strip():
            raise DeviceError("empty response to heartbeat command")
        return out
