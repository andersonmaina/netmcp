from __future__ import annotations

import re

from ..errors import DeviceError
from .base import Driver

_KV = re.compile(r'([\w.-]+)=("(?:[^"\\]|\\.)*"|\S*)')


def parse_terse(text: str) -> list[dict]:
    rows = []
    for line in text.splitlines():
        line = line.strip()
        if "=" not in line:
            continue
        row = {}
        m = re.match(r"^(\d+)\b", line)
        if m:
            row["_id"] = m.group(1)
        for k, v in _KV.findall(line):
            row[k] = v.strip('"')
        rows.append(row)
    return rows


class MikroTikDriver(Driver):
    family = "mikrotik"
    heartbeat_cmd = "/system identity print"
    error_re = re.compile(r"(?im)^.*(failure:|bad command name|syntax error|expected end of command|no such item|invalid value|input does not match|not enough permissions).*$")

    def normalize_read(self, cmd):
        cmd = cmd.strip()
        return cmd if cmd.startswith("/") else "/" + cmd

    def get_config(self, conn) -> str:
        return conn.send_command("/export hide-sensitive terse")

    def show(self, conn, cmd, parse=True):
        if re.match(r"^/ping\b", cmd) and "count=" not in cmd:
            cmd += " count=4"
        wants_rows = parse and re.search(r"(^|\s)print(\s|$)", cmd) and not re.search(
            r"\b(terse|detail|as-value|count-only|brief|interval|oid)\b", cmd)
        if wants_rows:
            cmd = re.sub(r"(^|\s)print(?=\s|$)", r"\1print terse", cmd, count=1)
        out = conn.send_command(cmd)
        if wants_rows:
            rows = parse_terse(out)
            if rows:
                return rows, True
        return out, False

    def arm_rollback(self, conn, minutes):
        """Binary backup + one-shot scheduler that restores it unless we remove the scheduler first."""
        h, m = divmod(int(minutes), 60)
        conn.send_command("/system scheduler remove [find name=netmcp-rollback]")
        for cmd in (
            "/system backup save name=netmcp-pre dont-encrypt=yes",
            f'/system scheduler add name=netmcp-rollback start-time=([/system clock get time]+{h:02d}:{m:02d}:00) '
            f'on-event="/system backup load name=netmcp-pre"',
        ):
            out = conn.send_command(cmd)
            if self.error_re.search(out or ""):
                raise DeviceError(f"could not arm rollback: {out.strip()[:200]}; nothing was changed")
        if "netmcp-rollback" not in conn.send_command("/system scheduler print where name=netmcp-rollback"):
            raise DeviceError("could not confirm the rollback scheduler exists; nothing was changed")
        return {"kind": "scheduler_restore", "minutes": int(minutes)}

    def disarm_rollback(self, conn, token):
        conn.send_command("/system scheduler remove [find name=netmcp-rollback]")
        if conn.send_command("/system scheduler print count-only where name=netmcp-rollback").strip() != "0":
            raise DeviceError("could not remove the rollback scheduler; the router may restore a backup")
        conn.send_command('/file remove [find name~"netmcp-pre"]')
