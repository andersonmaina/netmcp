import pytest

from netmcp.errors import PolicyDenied
from netmcp.policy import Policy


@pytest.fixture
def pol():
    return Policy({"protected": {"interfaces": ["GigabitEthernet0/0", "ether1"]}})


@pytest.mark.parametrize("cmd", [
    "show ip interface brief", "sh run", "sho ver", "show run | include ospf", "show run | section interface",
    "ping 8.8.8.8", "traceroute 8.8.8.8", "SHOW VERSION",
])
def test_cisco_reads_allowed(pol, cmd):
    pol.check_read("cisco", cmd)


@pytest.mark.parametrize("cmd", [
    "reload", "rel", "conf t", "configure terminal", "show run | redirect flash:x", "show run\nreload",
    "show run | tee flash:x", "ping", "s", "copy run tftp:", "write erase", "",
])
def test_cisco_reads_denied(pol, cmd):
    with pytest.raises(PolicyDenied):
        pol.check_read("cisco", cmd)


@pytest.mark.parametrize("cmd", [
    "/ip address print", "/interface print terse", "/export", "/export terse", "/system resource print",
    "/ip firewall filter print where chain=input", "/log print", "/interface monitor-traffic ether2 once",
])
def test_mikrotik_reads_allowed(pol, cmd):
    pol.check_read("mikrotik", cmd)


@pytest.mark.parametrize("cmd", [
    "/ip address add address=10.0.0.1/24 interface=ether2", "/system reset-configuration", "/system/reboot",
    "/sys reb", "/ip address print file=x", "/ip address print; /system reboot",
    "/ip address set [/system reboot]", "/system script run x", "/file print", "/ip address print\n/system reboot",
    "ip address print",  # no leading slash is normalized by the driver, but the policy itself wants absolute
])
def test_mikrotik_reads_denied(pol, cmd):
    with pytest.raises(PolicyDenied):
        pol.check_read("mikrotik", cmd)


@pytest.mark.parametrize("lines", [
    ["reload"], ["rel in 5"], ["do reload"], ["wr er"], ["copy tftp: running-config"], ["crypto key zeroize rsa"],
    ["configure replace flash:x force"], ["interface Gi0/1", "delete flash:x"],
])
def test_cisco_hard_deny(pol, lines):
    with pytest.raises(PolicyDenied):
        pol.assess("cisco", lines)


@pytest.mark.parametrize("lines", [
    ["/system reset-configuration"], ["/system/reboot"], ["/sys reb"], ["/system script run x"],
    ["/system scheduler remove [find]"], ["/tool fetch url=http://x"], ["/import file-name=x"],
    ["/ip address set [/system reboot]"], ["reset-configuration"], ["/ip address print; /system reboot"],
    ["/interface set [find] comment=[:execute x]"],
])
def test_mikrotik_hard_deny(pol, lines):
    with pytest.raises(PolicyDenied):
        pol.assess("mikrotik", lines)


def test_write_modes(pol):
    low = pol.assess("cisco", ["interface Gi0/1", "description uplink"])
    normal = pol.assess("cisco", ["interface Gi0/1", "ip address 10.0.0.1 255.255.255.0"])
    assert not pol.needs_approval(low, "supervised")
    assert pol.needs_approval(normal, "supervised")
    assert pol.needs_approval(low, "strict")
    assert not pol.needs_approval(normal, "autonomous")


def test_protected_interface_and_patterns(pol):
    a = pol.assess("cisco", ["interface gi0/0", "shutdown"])
    assert any(l.level == "protected" for l in a.lines)
    a = pol.assess("cisco", ["line vty 0 4", "transport input telnet"])
    assert all(l.level == "protected" for l in a.lines)
    assert pol.needs_approval(a, "supervised")
    a = pol.assess("mikrotik", ["/ip address set [find] interface=ether1"])
    assert a.lines[0].level == "protected"
    a = pol.assess("mikrotik", ["/ip service set ssh port=2222"])
    assert a.lines[0].level == "protected"


def test_user_lists_extend_defaults_never_replace():
    p = Policy({"hard_deny": {"cisco": ["debug"]}})
    with pytest.raises(PolicyDenied):
        p.assess("cisco", ["reload"])  # default still present
    with pytest.raises(PolicyDenied):
        p.assess("cisco", ["debug all"])  # user addition applied


def test_empty_plan_rejected(pol):
    with pytest.raises(PolicyDenied):
        pol.assess("cisco", ["", "! just a comment"])
