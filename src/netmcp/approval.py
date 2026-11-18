"""Human approval via the controlling terminal.

An agent's subprocess normally has no controlling TTY, so it cannot answer this prompt itself.
"""
from __future__ import annotations

import os

from .errors import ApprovalRequired


def tty_approver(summary: str) -> bool:
    try:
        if os.name == "nt":
            tin, tout = open("CONIN$", "r"), open("CONOUT$", "w")
        else:
            tin = tout = open("/dev/tty", "r+")
    except OSError:
        raise ApprovalRequired(
            "no controlling terminal available to ask for approval",
            hint="run this command yourself in a terminal, not through the agent's shell",
        )
    tout.write("\n" + summary + "\nType 'yes' to approve: ")
    tout.flush()
    return tin.readline().strip().lower() == "yes"


tty_approver.via = "tty"
