from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .errors import ConfigError, ConnectionFailed, NotFound

VENDORS = {
    "cisco_ios": "cisco",
    "cisco_xe": "cisco",
    "cisco_nxos": "cisco",
    "mikrotik_routeros": "mikrotik",
}


@dataclass
class Device:
    name: str
    host: str
    vendor: str
    username: str
    port: int = 22
    groups: list[str] = field(default_factory=list)
    verify: list[dict] = field(default_factory=list)
    mode: str | None = None  # per-device override of the global approval mode

    @property
    def family(self) -> str:
        return VENDORS[self.vendor]


class Inventory:
    def __init__(self, devices: dict[str, Device]):
        self.devices = devices

    @classmethod
    def load(cls, path: Path) -> "Inventory":
        path = Path(path)
        if not path.exists():
            return cls({})
        data = yaml.safe_load(path.read_text()) or {}
        devices = {}
        for name, d in (data.get("devices") or {}).items():
            if any(k in d for k in ("password", "secret", "enable_secret")):
                raise ConfigError(
                    f"device '{name}': passwords must not be stored in the inventory",
                    hint="use env vars NETMCP_<NAME>_PASSWORD / NETMCP_<NAME>_SECRET or the OS keyring",
                )
            if d.get("vendor") not in VENDORS:
                raise ConfigError(f"device '{name}': vendor must be one of {sorted(VENDORS)}")
            for req in ("host", "username"):
                if req not in d:
                    raise ConfigError(f"device '{name}': missing '{req}'")
            devices[name] = Device(
                name=name, host=d["host"], vendor=d["vendor"], username=d["username"],
                port=int(d.get("port", 22)), groups=list(d.get("groups", [])),
                verify=list(d.get("verify", [])), mode=d.get("mode"),
            )
        return cls(devices)

    def get(self, name: str) -> Device:
        if name not in self.devices:
            raise NotFound(f"unknown device '{name}'",
                           hint=f"known devices: {', '.join(sorted(self.devices)) or '(none; run `netmcp init`)'}")
        return self.devices[name]


def credentials(device: Device, env=None) -> tuple[str, str]:
    env = os.environ if env is None else env
    key = re.sub(r"\W", "_", device.name).upper()
    password = env.get(f"NETMCP_{key}_PASSWORD") or env.get("NETMCP_PASSWORD")
    secret = env.get(f"NETMCP_{key}_SECRET") or env.get("NETMCP_SECRET") or ""
    if password is None:
        try:
            import keyring  # optional

            password = keyring.get_password("netmcp", device.name)
            secret = secret or keyring.get_password("netmcp", f"{device.name}:secret") or ""
        except Exception:
            password = None
    if password is None:
        raise ConnectionFailed(
            f"no password available for '{device.name}'",
            hint=f"set NETMCP_{key}_PASSWORD, or: python -m keyring set netmcp {device.name}",
        )
    return password, secret
