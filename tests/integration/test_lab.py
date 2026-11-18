"""Lab tests against real/virtual devices (MikroTik CHR, Cisco CML/GNS3/IOSv). NOT run by default.

    NETMCP_LAB_HOME=/path/to/lab/netmcp-home  pytest -m integration

The home must contain an inventory with devices named in NETMCP_LAB_DEVICES (comma separated), a
policy with `mode: autonomous` and the management interface under protected.interfaces, and credentials in env.
The key test: push a change that kills management access and confirm the device rolls itself back.
"""
import os
import time

import pytest

from netmcp.home import Home
from netmcp.runtime import Runtime

pytestmark = pytest.mark.integration
LAB_HOME = os.environ.get("NETMCP_LAB_HOME")
DEVICES = [d for d in os.environ.get("NETMCP_LAB_DEVICES", "").split(",") if d]

if not LAB_HOME or not DEVICES:
    pytest.skip("set NETMCP_LAB_HOME and NETMCP_LAB_DEVICES to run lab tests", allow_module_level=True)

SHUTDOWN_MGMT = {  # adjust interface names to your lab topology
    "cisco": ["interface GigabitEthernet0/0", "shutdown"],
    "mikrotik": ["/interface ethernet disable ether1"],
}


@pytest.fixture(params=DEVICES)
def rt_dev(request):
    rt = Runtime(home=Home(LAB_HOME))
    return rt, rt.inventory.get(request.param)


def test_read_roundtrip(rt_dev):
    rt, dev = rt_dev
    assert rt.health(dev.name)["results"]


def test_harmless_change_applies_and_verifies(rt_dev):
    rt, dev = rt_dev
    line = (["interface GigabitEthernet0/1", "description netmcp-test"] if dev.family == "cisco"
            else ['/interface ethernet set ether2 comment="netmcp-test"'])
    assert rt.apply(rt.plan(dev.name, line)["plan_id"])["verified"]


def test_lockout_rolls_back_by_itself(rt_dev):
    """Kill management access, expect VerifyFailed, then expect the device to come back on its own."""
    from netmcp.errors import VerifyFailed
    rt, dev = rt_dev
    plan = rt.plan(dev.name, SHUTDOWN_MGMT[dev.family])
    with pytest.raises(VerifyFailed):
        rt.apply(plan["plan_id"])
    deadline = time.time() + (rt.policy.data["rollback_minutes"] + 6) * 60  # cisco reboots: allow time
    while time.time() < deadline:
        try:
            if rt.health(dev.name)["results"]:
                return
        except Exception:
            time.sleep(15)
    pytest.fail("device did not roll back and become reachable again")
