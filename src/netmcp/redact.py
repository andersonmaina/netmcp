from __future__ import annotations

import re

_PATTERNS = [
    # Cisco style: "password 7 XXXX", "secret 9 $9$...", "snmp-server community public RO"
    (re.compile(r"(?i)\b(password|secret|key-string|community|passphrase|pre-shared-key|private-key)(\s+\d)?(\s+)\S+"),
     r"\1\2\3<redacted>"),
    # RouterOS style: password=xxx, pre-shared-key="xxx"
    (re.compile(r"(?i)\b(password|passphrase|pre-shared-key|secret|private-key)=(\"[^\"]*\"|\S+)"),
     r"\1=<redacted>"),
]


def redact(text: str) -> str:
    for pat, repl in _PATTERNS:
        text = pat.sub(repl, text)
    return text


def redact_obj(obj):
    if isinstance(obj, str):
        return redact(obj)
    if isinstance(obj, list):
        return [redact_obj(x) for x in obj]
    if isinstance(obj, dict):
        return {k: redact_obj(v) for k, v in obj.items()}
    return obj
