from __future__ import annotations

import re

from ..errors import DeviceError
from .base import Driver


class CiscoDriver(Driver):
    family = "cisco"
    heartbeat_cmd = "show clock"
    error_re = re.compile(r"(?im)^.*(invalid input|incomplete command|ambiguous command|unknown command|unrecognized command).*$")

    def get_config(self, conn) -> str:
        return conn.send_command("show running-config")

    def show(self, conn, cmd, parse=True):
        if parse:
            try:
                out = conn.send_command(cmd, use_textfsm=True)
            except Exception:
                out = conn.send_command(cmd)
            if isinstance(out, (list, dict)):
                return out, True
            return out, False
        return conn.send_command(cmd), False

    def arm_rollback(self, conn, minutes):
        """`reload in N` as a dead-man's switch: if we never cancel it, the box reboots into startup-config.

        Because nothing is saved until verification passes, startup-config == the pre-change state
        (assuming it was saved before). The timer is verified via `show reload`; if we can't confirm it is
        armed we refuse to proceed.
        """
        out = conn.send_command_timing(f"reload in {int(minutes)}")
        for _ in range(4):
            low = out.lower()
            if "save?" in low or "[yes/no]" in low:
                out = conn.send_command_timing("no")  # never save as a side effect
            elif "[confirm]" in low or "proceed with reload" in low:
                out = conn.send_command_timing("")
            else:
                break
        low = conn.send_command("show reload").lower()
        if "reload scheduled" not in low or "no reload" in low:
            raise DeviceError("could not confirm the rollback timer is armed; nothing was changed")
        return {"kind": "reload_in", "minutes": int(minutes)}

    def disarm_rollback(self, conn, token):
        conn.send_command_timing("reload cancel")
        if "no reload" not in conn.send_command("show reload").lower():
            raise DeviceError("could not cancel the scheduled reload; the device may reboot")

    def persist(self, conn) -> bool:
        conn.save_config()
        return True
