import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).parent))
from fakes import FakeNet  # noqa: E402

from netmcp.home import Home  # noqa: E402
from netmcp.runtime import Runtime  # noqa: E402


class Clock:
    def __init__(self):
        self.t = 1_800_000_000.0

    def __call__(self):
        return self.t


@pytest.fixture
def make_rt(tmp_path):
    def _make(vendor="cisco_ios", mode="strict", verify=None, policy_extra=None):
        home = Home(tmp_path)
        home.ensure()
        dev = {"host": "192.0.2.1", "vendor": vendor, "username": "admin"}
        if verify:
            dev["verify"] = verify
        home.inventory_path.write_text(yaml.safe_dump({"devices": {"r1": dev}}))
        home.policy_path.write_text(yaml.safe_dump({"mode": mode, **(policy_extra or {})}))
        net = FakeNet(vendor)
        clock = Clock()
        return Runtime(home=home, connect=net.connect, clock=clock), net, clock
    return _make


def yes(_summary):
    return True


def no(_summary):
    return False
