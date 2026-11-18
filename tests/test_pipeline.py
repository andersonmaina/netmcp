import json

import pytest

from conftest import no, yes
from netmcp.errors import ApprovalRequired, DeviceError, NotFound, PolicyDenied, VerifyFailed

VENDORS = ["cisco_ios", "mikrotik_routeros"]
CHANGE = {"cisco_ios": ["interface Gi0/1", "description uplink"],
          "mikrotik_routeros": ['/interface ethernet set ether2 comment="uplink"']}


def audit_events(rt):
    return [json.loads(l)["event"] for l in rt.home.audit_path.read_text().splitlines()]


@pytest.mark.parametrize("vendor", VENDORS)
def test_strict_requires_approval_then_applies(make_rt, vendor):
    rt, net, _ = make_rt(vendor, "strict")
    plan = rt.plan("r1", CHANGE[vendor])
    assert plan["needs_approval"]
    with pytest.raises(ApprovalRequired):
        rt.apply(plan["plan_id"])
    assert not net.timer_armed and net.connects == 0  # nothing touched the device
    rt.approve(plan["plan_id"], yes)
    res = rt.apply(plan["plan_id"])
    assert res["applied"] and res["verified"] and res["rollback"] == "disarmed"
    assert not net.timer_armed
    assert net.saved == (vendor == "cisco_ios")
    assert CHANGE[vendor][-1] in net.config
    assert "+" + CHANGE[vendor][-1] in res["diff"]
    assert list((rt.home.backups_dir / "r1").glob("*.cfg"))
    ev = audit_events(rt)
    assert ev[-4:] == ["approve", "apply_start", "backup", "apply_ok"]


@pytest.mark.parametrize("vendor", VENDORS)
def test_autonomous_applies_without_approval(make_rt, vendor):
    rt, net, _ = make_rt(vendor, "autonomous")
    plan = rt.plan("r1", CHANGE[vendor])
    assert not plan["needs_approval"]
    assert rt.apply(plan["plan_id"])["applied"]


@pytest.mark.parametrize("vendor", VENDORS)
def test_declined_approval_blocks(make_rt, vendor):
    rt, net, _ = make_rt(vendor, "strict")
    plan = rt.plan("r1", CHANGE[vendor])
    with pytest.raises(ApprovalRequired):
        rt.approve(plan["plan_id"], no)
    with pytest.raises(ApprovalRequired):
        rt.apply(plan["plan_id"])


@pytest.mark.parametrize("vendor,line", [("cisco_ios", "reload"), ("mikrotik_routeros", "/system reboot")])
def test_denied_plan_never_created(make_rt, vendor, line):
    rt, net, _ = make_rt(vendor, "autonomous")
    with pytest.raises(PolicyDenied):
        rt.plan("r1", [line])
    assert not list(rt.home.plans_dir.glob("*.json"))
    assert "plan_denied" in audit_events(rt)


@pytest.mark.parametrize("vendor", VENDORS)
def test_lockout_leaves_rollback_armed(make_rt, vendor):
    rt, net, _ = make_rt(vendor, "autonomous")
    plan = rt.plan("r1", CHANGE[vendor])
    net.fail_connect_from = 2  # the verification connection fails: management access lost
    with pytest.raises(VerifyFailed) as e:
        rt.apply(plan["plan_id"])
    assert net.timer_armed  # dead-man's switch still armed
    assert not net.saved
    assert "rollback" in str(e.value).lower()
    with pytest.raises(PolicyDenied):  # failed plans cannot be replayed
        rt.apply(plan["plan_id"])


@pytest.mark.parametrize("vendor", VENDORS)
def test_failed_verify_check_leaves_rollback_armed(make_rt, vendor):
    chk = "show ip interface brief" if vendor == "cisco_ios" else "/interface print"
    rt, net, _ = make_rt(vendor, "autonomous", verify=[{"cmd": chk, "contains": "NOPE-NOT-THERE"}])
    plan = rt.plan("r1", CHANGE[vendor])
    with pytest.raises(VerifyFailed):
        rt.apply(plan["plan_id"])
    assert net.timer_armed and not net.saved


@pytest.mark.parametrize("vendor", VENDORS)
def test_verify_check_passes(make_rt, vendor):
    chk, want = (("show ip interface brief", "interface") if vendor == "cisco_ios" else ("/interface print", "ether1"))
    rt, net, _ = make_rt(vendor, "autonomous", verify=[{"cmd": chk, "contains": want}])
    assert rt.apply(rt.plan("r1", CHANGE[vendor])["plan_id"])["verified"]


@pytest.mark.parametrize("vendor", VENDORS)
def test_refuses_to_change_anything_if_rollback_cannot_arm(make_rt, vendor):
    rt, net, _ = make_rt(vendor, "autonomous")
    plan = rt.plan("r1", CHANGE[vendor])
    before = list(net.config)
    net.arm_fails = True
    with pytest.raises(DeviceError):
        rt.apply(plan["plan_id"])
    assert net.config == before


@pytest.mark.parametrize("vendor", VENDORS)
def test_device_rejecting_a_command_reports_armed_rollback(make_rt, vendor):
    rt, net, _ = make_rt(vendor, "autonomous")
    plan = rt.plan("r1", CHANGE[vendor])
    net.bad_apply = True
    with pytest.raises(DeviceError) as e:
        rt.apply(plan["plan_id"])
    assert net.timer_armed
    assert "rollback timer is armed" in e.value.hint


@pytest.mark.parametrize("vendor", VENDORS)
def test_cancel_failure_is_not_silent(make_rt, vendor):
    rt, net, _ = make_rt(vendor, "autonomous")
    plan = rt.plan("r1", CHANGE[vendor])
    net.cancel_fails = True
    with pytest.raises(VerifyFailed):
        rt.apply(plan["plan_id"])
    assert net.timer_armed and not net.saved


def test_plan_expires(make_rt):
    rt, net, clock = make_rt("cisco_ios", "autonomous")
    plan = rt.plan("r1", CHANGE["cisco_ios"])
    clock.t += 31 * 60
    with pytest.raises(PolicyDenied):
        rt.apply(plan["plan_id"])


def test_tampered_plan_rejected(make_rt):
    rt, net, _ = make_rt("cisco_ios", "autonomous")
    plan = rt.plan("r1", CHANGE["cisco_ios"])
    p = rt.home.plans_dir / f"{plan['plan_id']}.json"
    data = json.loads(p.read_text())
    data["lines"].append("username evil privilege 15 secret x")
    p.write_text(json.dumps(data))
    with pytest.raises(PolicyDenied):
        rt.apply(plan["plan_id"])
    assert net.connects == 0


def test_tightened_policy_is_enforced_at_apply_time(make_rt):
    rt, net, _ = make_rt("cisco_ios", "autonomous")
    plan = rt.plan("r1", CHANGE["cisco_ios"])
    rt.policy.write_mode("strict")  # operator tightens after planning
    with pytest.raises(ApprovalRequired):
        rt.apply(plan["plan_id"])


def test_mode_loosening_needs_human_tightening_does_not(make_rt):
    rt, _, _ = make_rt("cisco_ios", "strict")
    with pytest.raises(ApprovalRequired):
        rt.set_mode("autonomous")  # no approver (e.g. an agent calling it)
    with pytest.raises(ApprovalRequired):
        rt.set_mode("autonomous", no)
    assert rt.set_mode("autonomous", yes)["mode"] == "autonomous"
    assert rt.set_mode("strict")["mode"] == "strict"  # tightening is free
    assert "mode: strict" in rt.home.policy_path.read_text()


@pytest.mark.parametrize("vendor,cmd", [("cisco_ios", "reload"), ("mikrotik_routeros", "/system reboot"),
                                        ("cisco_ios", "conf t")])
def test_show_rejects_writes_before_connecting(make_rt, vendor, cmd):
    rt, net, _ = make_rt(vendor)
    with pytest.raises(PolicyDenied):
        rt.show("r1", [cmd])
    assert net.connects == 0


def test_show_cisco_and_mikrotik(make_rt):
    rt, net, _ = make_rt("cisco_ios")
    out = rt.show("r1", ["sh ip int br"])
    assert out["results"][0]["command"] == "sh ip int br"
    rt, net, _ = make_rt("mikrotik_routeros")
    out = rt.show("r1", ["interface print"])  # leading slash added, terse parsing applied
    r = out["results"][0]
    assert r["command"] == "/interface print terse" or r["command"] == "/interface print"
    assert r["parsed"] and r["output"][0]["name"] == "ether1"


def test_backup_and_diff(make_rt):
    rt, net, _ = make_rt("cisco_ios", "autonomous")
    rt.backup("r1")
    assert rt.diff("r1")["changed"] is False
    net.config.append("ntp server 192.0.2.50")
    d = rt.diff("r1")
    assert d["changed"] and "+ntp server 192.0.2.50" in d["diff"]


def test_diff_without_backup(make_rt):
    rt, _, _ = make_rt("cisco_ios")
    with pytest.raises(NotFound):
        rt.diff("r1")


def test_audit_redacts_secrets(make_rt):
    rt, net, _ = make_rt("cisco_ios", "autonomous")
    rt.plan("r1", ["username bob secret 9 $9$topsecrethash"])
    assert "topsecrethash" not in rt.home.audit_path.read_text()
