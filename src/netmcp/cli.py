from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .api import run
from .approval import tty_approver
from .errors import NetmcpError
from .home import Home
from .runtime import Runtime

SAMPLE_INVENTORY = """# Passwords never go here. Use NETMCP_<NAME>_PASSWORD env vars or the OS keyring.
devices:
  lab-cisco:
    host: 192.0.2.10
    vendor: cisco_ios          # cisco_ios | cisco_xe | cisco_nxos | mikrotik_routeros
    username: admin
    groups: [lab]
    verify:                    # optional extra post-change checks (read-only commands)
      - cmd: show ip interface brief
        contains: GigabitEthernet0/0
  lab-mikrotik:
    host: 192.0.2.20
    vendor: mikrotik_routeros
    username: admin
"""

SAMPLE_POLICY = """# strict: every change needs human approval (default)
# supervised: low-risk changes auto-apply, everything else needs approval
# autonomous: the agent applies changes itself (hard-deny list, backup and rollback still apply)
mode: strict
rollback_minutes: 5
protected:
  interfaces: []               # management interfaces, e.g. [GigabitEthernet0/0] or [ether1]
# hard_deny / protected.patterns lists here are ADDED to the built-in defaults.
"""


def init_home() -> dict:
    home = Home()
    home.ensure()
    created = []
    for path, text in ((home.inventory_path, SAMPLE_INVENTORY), (home.policy_path, SAMPLE_POLICY)):
        if not path.exists():
            path.write_text(text)
            created.append(str(path))
    return {"home": str(home.root), "created": created}


def _read_lines(args) -> list[str]:
    lines = list(args.line or [])
    if args.file:
        text = sys.stdin.read() if args.file == "-" else Path(args.file).read_text()
        lines.extend(text.splitlines())
    if not lines:
        raise NetmcpError("no config lines given", hint="use --line (repeatable), --file PATH, or --file -")
    return lines


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="netmcp", description="Safe Cisco/MikroTik tooling for AI agents.")
    p.add_argument("--pretty", action="store_true", help="indent JSON output")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init", help="create ~/.netmcp with sample inventory and policy")
    sub.add_parser("version")
    inv = sub.add_parser("inventory"); inv.add_argument("action", choices=["list"])
    s = sub.add_parser("show", help="run read-only commands"); s.add_argument("device"); s.add_argument("commands", nargs="+")
    s.add_argument("--raw", action="store_true", help="skip structured parsing")
    for name in ("backup", "health"):
        x = sub.add_parser(name); x.add_argument("device")
    d = sub.add_parser("diff"); d.add_argument("device"); d.add_argument("--against", default="latest")
    pl = sub.add_parser("plan", help="validate a change and create a plan (touches nothing)")
    pl.add_argument("device"); pl.add_argument("--line", action="append"); pl.add_argument("--file"); pl.add_argument("--note", default="")
    ap = sub.add_parser("apply"); ap.add_argument("plan_id")
    aprv = sub.add_parser("approve", help="HUMAN ONLY: approve a plan (asks on the controlling terminal)"); aprv.add_argument("plan_id")
    m = sub.add_parser("mode"); m.add_argument("action", choices=["show", "set"]); m.add_argument("value", nargs="?")
    sub.add_parser("serve", help="run the MCP server (stdio)")
    return p


def dispatch(a):
    if a.cmd == "init":
        return init_home()
    if a.cmd == "version":
        return {"version": __version__}
    if a.cmd == "serve":
        from .mcp_server import main as serve
        serve()
        return {}
    rt = Runtime()
    if a.cmd == "inventory":
        return rt.inventory_list()
    if a.cmd == "show":
        return rt.show(a.device, a.commands, parse=not a.raw)
    if a.cmd == "backup":
        return rt.backup(a.device)
    if a.cmd == "health":
        return rt.health(a.device)
    if a.cmd == "diff":
        return rt.diff(a.device, a.against)
    if a.cmd == "plan":
        return rt.plan(a.device, _read_lines(a), a.note)
    if a.cmd == "apply":
        return rt.apply(a.plan_id)
    if a.cmd == "approve":
        return rt.approve(a.plan_id, tty_approver)
    if a.cmd == "mode":
        if a.action == "show":
            return rt.mode_info()
        if not a.value:
            raise NetmcpError("usage: netmcp mode set <strict|supervised|autonomous>")
        return rt.set_mode(a.value, tty_approver)


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    env, code = run(lambda: dispatch(args))
    if args.cmd == "serve" and code == 0:
        return 0
    print(json.dumps(env, indent=2 if args.pretty else None))
    return code
