"""Policy engine: decides what an agent may read, what it may change, and what needs a human.

Matching is token-based and abbreviation-aware (IOS accepts `rel` for `reload`, RouterOS accepts
`/sys reb`), so a hard-deny rule matches any command whose tokens are *prefixes* of the rule's tokens.
This is deliberately conservative: it may over-deny ambiguous abbreviations, never under-deny them.
Pattern-based checks (protected/low-risk) are best-effort; the rollback timer is the real safety net.
"""
from __future__ import annotations

import copy
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .errors import ConfigError, PolicyDenied

MODES = ("strict", "supervised", "autonomous")  # ordered from safest to loosest

DEFAULT_POLICY: dict = {
    "mode": "strict",
    "rollback_minutes": 5,
    "plan_ttl_minutes": 30,
    "redact_output": True,
    # Lists in a user policy file are APPENDED to these defaults, never replace them.
    "hard_deny": {
        "cisco": ["reload", "erase", "write erase", "format", "delete", "copy", "boot",
                  "crypto key zeroize", "tclsh", "configure replace"],
        "mikrotik": ["system reset-configuration", "system reboot", "system shutdown",
                     "system routerboard", "system package", "system upgrade", "system script",
                     "system scheduler", "system backup load", "tool fetch", "import", "file",
                     ":execute"],
    },
    "protected": {
        "interfaces": [],  # e.g. ["GigabitEthernet0/0"] for cisco, ["ether1"] for mikrotik
        "patterns": {
            "cisco": [r"^line\s+(vty|con|aux)", r"\bip\s+ssh\b", r"^(no\s+)?username\b",
                      r"^(no\s+)?enable\s+(secret|password)", r"^(no\s+)?aaa\b",
                      r"^transport\s+input\b", r"^(no\s+)?crypto\s+key",
                      r"^(no\s+)?ip\s+route\s+0\.0\.0\.0\s+0\.0\.0\.0", r"^(no\s+)?access-class\b"],
            "mikrotik": [r"^user\b", r"^ip service\b", r"^ip ssh\b", r"^ip firewall\b",
                         r"^ip address\b", r"^ip route\b", r"^ip dhcp-client\b",
                         r"^interface\s+(\S+\s+)?(remove|disable)\b", r"^radius\b"],
        },
    },
    "low_risk": {
        "cisco": [r"^interface\s+\S+$", r"^exit$", r"^end$", r"^(no\s+)?description\b"],
        "mikrotik": [r"^interface\s+(\S+\s+)?set\s+\S+\s+comment="],
    },
}


def _merge(base: dict, extra: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (extra or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        elif isinstance(v, list) and isinstance(out.get(k), list):
            out[k] = out[k] + v
        else:
            out[k] = v
    return out


def prefix_match(cmd_tokens: list[str], rule_tokens: list[str]) -> bool:
    if len(cmd_tokens) < len(rule_tokens):
        return False
    return all(rule.startswith(tok) for tok, rule in zip(cmd_tokens, rule_tokens))


# ---------- Cisco helpers ----------
_IFACE_NAMES = ["gigabitethernet", "tengigabitethernet", "fastethernet", "ethernet", "loopback",
                "vlan", "tunnel", "port-channel", "serial", "management"]
_CTX_ENTRY = re.compile(r"^(interface|line|router|vlan|ip access-list|ipv6 access-list|route-map|policy-map|"
                        r"class-map|crypto|vrf definition|control-plane|archive|key chain)\b")
_CISCO_READ_FIRST = ("show", "ping", "traceroute")
_CISCO_FILTERS = ("include", "exclude", "begin", "section", "count")


def canon_iface(name: str) -> str:
    n = name.lower().strip()
    m = re.match(r"^([a-z-]+?)\s*(\d[\d/.:]*)$", n)
    if not m:
        return n
    pre, num = m.groups()
    if len(pre) >= 2:
        for full in _IFACE_NAMES:
            if full.startswith(pre):
                return full + num
    return n


# ---------- MikroTik helpers ----------
_MT_READ = ("print", "export", "get", "find", "monitor-traffic", "monitor", "ping")
_MT_WRITE = ("add", "set", "remove", "enable", "disable", "unset", "move", "edit", "comment", "reset",
             "reset-configuration", "import", "run", "load", "save", "upgrade", "reboot", "shutdown",
             "execute", "fetch", "scan", "clear", "flush", "release", "renew", "new", "copy", "install")
_MT_BAD_CHARS = (";", "{", "}", "`", "\n", "\r")


def mt_path_tokens(line: str) -> list[str]:
    out = []
    for t in line.strip().lower().split():
        if "=" in t:
            break
        out.extend(p for p in t.split("/") if p)
    return out


def mt_norm(line: str) -> str:
    out, in_path = [], True
    for t in line.strip().lower().split():
        if in_path and "=" in t:
            in_path = False
        out.extend([p for p in t.split("/") if p] if in_path else [t])
    return " ".join(out)


def mt_pieces(line: str) -> list[str]:
    """The line plus the contents of every [ ... ] sub-expression (RouterOS runs those as commands)."""
    pieces, s = [line], line
    while True:
        found = re.findall(r"\[([^\[\]]*)\]", s)
        if not found:
            return pieces
        pieces += [f.strip() for f in found]
        s = re.sub(r"\[[^\[\]]*\]", "", s)


def mt_is_read(line: str) -> bool:
    toks = mt_path_tokens(line)
    if any(any(v.startswith(t) for v in _MT_WRITE) for t in toks):
        return False
    return any(any(v.startswith(t) for v in _MT_READ) for t in toks)


@dataclass
class LineInfo:
    line: str
    level: str  # deny | protected | normal | low
    reason: str = ""


@dataclass
class Assessment:
    lines: list[LineInfo] = field(default_factory=list)

    @property
    def denied(self) -> list[LineInfo]:
        return [l for l in self.lines if l.level == "deny"]

    def flags(self) -> list[dict]:
        return [{"line": l.line, "level": l.level, "reason": l.reason}
                for l in self.lines if l.level in ("protected", "deny")]


class Policy:
    def __init__(self, data: dict | None = None, path: Path | None = None):
        self.data = _merge(DEFAULT_POLICY, data or {})
        self.path = path
        if self.data["mode"] not in MODES:
            raise ConfigError(f"policy mode must be one of {MODES}")

    @classmethod
    def load(cls, path: Path) -> "Policy":
        path = Path(path)
        data = yaml.safe_load(path.read_text()) if path.exists() else {}
        return cls(data or {}, path)

    @property
    def mode(self) -> str:
        return self.data["mode"]

    def mode_for(self, device) -> str:
        m = device.mode or self.mode
        if m not in MODES:
            raise ConfigError(f"device '{device.name}': invalid mode '{m}'")
        return m

    # ----- reads -----
    def check_read(self, family: str, command: str) -> str:
        cmd = command.strip()
        if not cmd or len(cmd) > 500 or any(c in cmd for c in "\r\n\x00"):
            raise PolicyDenied("empty, oversized, or multi-line command", hint="send one command per entry")
        return self._read_cisco(cmd) if family == "cisco" else self._read_mikrotik(cmd)

    def _read_cisco(self, cmd: str) -> str:
        head, *filters = [p.strip() for p in " ".join(cmd.lower().split()).split("|")]
        toks = head.split()
        if (not toks or len(toks[0]) < 2
                or not any(f.startswith(toks[0]) for f in _CISCO_READ_FIRST)):
            raise PolicyDenied(f"'{cmd}' is not a read-only command",
                               hint="only show/ping/traceroute are allowed here; use `plan` + `apply` for changes")
        if any(f.startswith(toks[0]) for f in ("ping", "traceroute")) and len(toks) < 2:
            raise PolicyDenied("ping/traceroute need a target (the interactive form would hang)")
        for f in filters:
            ft = f.split()
            if not ft or not any(x.startswith(ft[0]) for x in _CISCO_FILTERS):
                raise PolicyDenied(f"output modifier '{f}' is not allowed (only include/exclude/begin/section/count)")
        return cmd

    def _read_mikrotik(self, cmd: str) -> str:
        if any(c in cmd for c in _MT_BAD_CHARS):
            raise PolicyDenied("command separators and braces are not allowed")
        if not cmd.startswith("/"):
            raise PolicyDenied("MikroTik commands must be absolute paths starting with '/'")
        self._mt_check_deny(cmd)
        if not mt_is_read(cmd) or re.search(r"\bfile=", cmd):
            raise PolicyDenied(f"'{cmd}' is not a read-only command",
                               hint="only print/export/get/find/monitor/ping are allowed here")
        return cmd

    def _mt_check_deny(self, line: str) -> None:
        rules = [r.split() for r in self.data["hard_deny"]["mikrotik"]]
        for piece in mt_pieces(line):
            if piece.startswith("/") or piece.startswith(":"):
                toks = mt_path_tokens(piece) if piece.startswith("/") else [piece.split()[0].lower()]
                if any(prefix_match(toks, r) for r in rules):
                    raise PolicyDenied(f"'{piece}' is hard-denied", hint="this command can never be run via netmcp")

    # ----- writes -----
    def assess(self, family: str, lines: list[str]) -> Assessment:
        a = self._assess_cisco(lines) if family == "cisco" else self._assess_mikrotik(lines)
        if a.denied:
            raise PolicyDenied("; ".join(f"'{d.line}': {d.reason}" for d in a.denied),
                               hint="remove the denied lines and plan again")
        if not a.lines:
            raise PolicyDenied("plan contains no commands")
        return a

    def _assess_cisco(self, lines: list[str]) -> Assessment:
        deny = [r.split() for r in self.data["hard_deny"]["cisco"]]
        prot_pats = [re.compile(p, re.I) for p in self.data["protected"]["patterns"]["cisco"]]
        low_pats = [re.compile(p, re.I) for p in self.data["low_risk"]["cisco"]]
        prot_if = {canon_iface(i) for i in self.data["protected"]["interfaces"]}
        out, ctx = Assessment(), ""
        for raw in lines:
            line = raw.strip()
            if not line or line.startswith("!"):
                continue
            low = " ".join(line.lower().split())
            execp = low
            while execp.startswith("do "):
                execp = execp[3:]
            toks = execp.split()
            if any(prefix_match(toks, r) for r in deny):
                out.lines.append(LineInfo(line, "deny", "hard-denied command"))
                continue
            if low in ("exit", "end"):
                ctx = ""
            elif _CTX_ENTRY.match(low):
                ctx = low
            in_prot_if = ctx.startswith("interface ") and canon_iface(ctx.split(None, 1)[1]) in prot_if
            mentions = any(canon_iface(t) in prot_if for t in toks[1:]) if prot_if else False
            if in_prot_if or mentions:
                out.lines.append(LineInfo(line, "protected", "touches a protected interface"))
            elif any(p.search(low) or (ctx and p.search(ctx) and not _CTX_ENTRY.match(low) and low not in ("exit", "end"))
                     for p in prot_pats):
                out.lines.append(LineInfo(line, "protected", "management-plane or access-related"))
            elif any(p.search(low) for p in low_pats):
                out.lines.append(LineInfo(line, "low"))
            else:
                out.lines.append(LineInfo(line, "normal"))
        return out

    def _assess_mikrotik(self, lines: list[str]) -> Assessment:
        deny = [r.split() for r in self.data["hard_deny"]["mikrotik"]]
        prot_pats = [re.compile(p, re.I) for p in self.data["protected"]["patterns"]["mikrotik"]]
        low_pats = [re.compile(p, re.I) for p in self.data["low_risk"]["mikrotik"]]
        prot_if = [i.lower() for i in self.data["protected"]["interfaces"]]
        out = Assessment()
        for raw in lines:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if not line.startswith("/"):
                out.lines.append(LineInfo(line, "deny", "every line must be an absolute command starting with '/'"))
                continue
            if any(c in line for c in _MT_BAD_CHARS):
                out.lines.append(LineInfo(line, "deny", "separators/braces are not allowed"))
                continue
            denied = False
            for piece in mt_pieces(line):
                if piece.startswith("/") or piece.startswith(":"):
                    toks = mt_path_tokens(piece) if piece.startswith("/") else [piece.split()[0].lower()]
                    if any(prefix_match(toks, r) for r in deny):
                        out.lines.append(LineInfo(line, "deny", f"hard-denied command in '{piece}'"))
                        denied = True
                        break
            if denied:
                continue
            norm = mt_norm(line)
            if any(re.search(rf"(?<![\w-]){re.escape(i)}(?![\w-])", norm) for i in prot_if):
                out.lines.append(LineInfo(line, "protected", "touches a protected interface"))
            elif any(p.search(norm) for p in prot_pats):
                out.lines.append(LineInfo(line, "protected", "management-plane or addressing/routing/firewall"))
            elif any(p.search(norm) for p in low_pats):
                out.lines.append(LineInfo(line, "low"))
            else:
                out.lines.append(LineInfo(line, "normal"))
        return out

    def needs_approval(self, a: Assessment, mode: str) -> bool:
        if mode == "strict":
            return True
        if mode == "autonomous":
            return False
        return any(l.level in ("protected", "normal") for l in a.lines)

    # ----- persistence of the mode setting -----
    def write_mode(self, mode: str) -> None:
        if mode not in MODES:
            raise ConfigError(f"mode must be one of {MODES}")
        self.data["mode"] = mode
        if not self.path:
            return
        text = self.path.read_text() if self.path.exists() else ""
        if re.search(r"(?m)^mode:.*$", text):
            text = re.sub(r"(?m)^mode:.*$", f"mode: {mode}", text)
        else:
            text = f"mode: {mode}\n" + text
        self.path.write_text(text)
