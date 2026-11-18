import json

from netmcp import cli


def run(capsys, monkeypatch, tmp_path, *argv):
    monkeypatch.setenv("NETMCP_HOME", str(tmp_path))
    code = cli.main(list(argv))
    return code, json.loads(capsys.readouterr().out)


def test_init_and_inventory(capsys, monkeypatch, tmp_path):
    code, out = run(capsys, monkeypatch, tmp_path, "init")
    assert code == 0 and out["ok"]
    code, out = run(capsys, monkeypatch, tmp_path, "inventory", "list")
    assert code == 0 and {d["name"] for d in out["data"]["devices"]} == {"lab-cisco", "lab-mikrotik"}


def test_exit_codes_and_hints(capsys, monkeypatch, tmp_path):
    run(capsys, monkeypatch, tmp_path, "init")
    code, out = run(capsys, monkeypatch, tmp_path, "plan", "lab-cisco", "--line", "reload")
    assert code == 2 and out["error"]["code"] == "policy_denied"
    code, out = run(capsys, monkeypatch, tmp_path, "show", "nope", "show clock")
    assert code == 6 and "known devices" in out["error"]["hint"]
    code, out = run(capsys, monkeypatch, tmp_path, "plan", "lab-cisco", "--line", "interface Gi0/1", "--line", "description x")
    assert code == 0 and out["data"]["needs_approval"] is True  # default mode is strict
    code, out = run(capsys, monkeypatch, tmp_path, "apply", out["data"]["plan_id"])
    assert code == 3 and "approve" in out["error"]["hint"]


def test_agent_cannot_approve_without_a_tty(capsys, monkeypatch, tmp_path):
    run(capsys, monkeypatch, tmp_path, "init")
    _, plan = run(capsys, monkeypatch, tmp_path, "plan", "lab-cisco", "--line", "description x")
    monkeypatch.setattr("builtins.open", lambda *a, **k: (_ for _ in ()).throw(OSError("no tty")))
    from netmcp.approval import tty_approver
    import pytest
    from netmcp.errors import ApprovalRequired
    with pytest.raises(ApprovalRequired):
        tty_approver("x")
