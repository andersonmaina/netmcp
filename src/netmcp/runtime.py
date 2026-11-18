from __future__ import annotations

import difflib
import hashlib
import os
import re
import time
from contextlib import contextmanager
from datetime import datetime, timezone

from .audit import Audit
from .drivers import get_driver
from .errors import (ApprovalRequired, ConnectionFailed, DeviceError, NetmcpError, NotFound,
                     PolicyDenied, VerifyFailed)
from .home import Home
from .inventory import Inventory, credentials
from .plans import PlanStore, digest
from .policy import MODES, Policy
from .redact import redact, redact_obj

_VOLATILE = {
    "cisco": re.compile(r"^(!|building configuration|current configuration|ntp clock-period)", re.I),
    "mikrotik": re.compile(r"^#"),
}


def _normalize(family: str, text: str) -> list[str]:
    return [l.rstrip() for l in text.splitlines() if l.strip() and not _VOLATILE[family].match(l.strip())]


def netmiko_connect(device, env=None):
    from netmiko import ConnectHandler  # lazy: netmiko is slow to import
    from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

    password, secret = credentials(device, env)
    try:
        conn = ConnectHandler(device_type=device.vendor, host=device.host, port=device.port,
                              username=device.username, password=password, secret=secret,
                              conn_timeout=15, auth_timeout=15, banner_timeout=15)
        if device.family == "cisco" and secret:
            conn.enable()
        return conn
    except NetmikoAuthenticationException:
        raise ConnectionFailed(f"authentication failed for '{device.name}'", hint="check username and password")
    except NetmikoTimeoutException:
        raise ConnectionFailed(f"timed out connecting to '{device.name}' ({device.host}:{device.port})",
                               hint="check reachability and that SSH is enabled")
    except OSError as e:
        raise ConnectionFailed(f"cannot reach '{device.name}': {e}")


class Runtime:
    def __init__(self, home: Home | None = None, connect=None, clock=time.time, env=None,
                 policy: Policy | None = None, inventory: Inventory | None = None):
        self.home = home or Home()
        self.home.ensure()
        self.clock = clock
        self.env = env
        self._connect = connect or (lambda device: netmiko_connect(device, self.env))
        self.policy = policy or Policy.load(self.home.policy_path)
        self.inventory = inventory or Inventory.load(self.home.inventory_path)
        self.audit = Audit(self.home.audit_path, clock)
        self.plans = PlanStore(self.home.plans_dir, clock)

    # ---------- plumbing ----------
    @contextmanager
    def _session(self, device):
        driver = get_driver(device)
        conn = self._connect(device)
        try:
            yield conn, driver
        except NetmcpError:
            raise
        except Exception as e:  # netmiko/paramiko errors
            raise DeviceError(f"{type(e).__name__}: {e}") from e
        finally:
            try:
                conn.disconnect()
            except Exception:
                pass

    def _clean(self, data):
        return redact_obj(data) if self.policy.data["redact_output"] else data

    # ---------- reads ----------
    def inventory_list(self) -> dict:
        return {"devices": [{"name": d.name, "host": d.host, "vendor": d.vendor, "groups": d.groups,
                             "mode": self.policy.mode_for(d)} for d in self.inventory.devices.values()]}

    def show(self, device_name: str, commands: list[str], parse: bool = True) -> dict:
        device = self.inventory.get(device_name)
        driver = get_driver(device)
        try:
            cmds = [self.policy.check_read(device.family, driver.normalize_read(c)) for c in commands]
        except PolicyDenied as e:
            self.audit.log("show_denied", device=device.name, commands=commands, reason=str(e))
            raise
        results = []
        with self._session(device) as (conn, drv):
            for c in cmds:
                data, parsed = drv.show(conn, c, parse)
                results.append({"command": c, "parsed": parsed, "output": self._clean(data)})
        self.audit.log("show", device=device.name, commands=cmds)
        return {"device": device.name, "results": results}

    def health(self, device_name: str) -> dict:
        device = self.inventory.get(device_name)
        cmds = (["show clock", "show ip interface brief"] if device.family == "cisco"
                else ["/system resource print", "/interface print"])
        return self.show(device_name, cmds)

    def backup(self, device_name: str) -> dict:
        device = self.inventory.get(device_name)
        with self._session(device) as (conn, drv):
            cfg = drv.get_config(conn)
        return self._store_backup(device, cfg)

    def _store_backup(self, device, cfg: str) -> dict:
        d = self.home.backups_dir / device.name
        d.mkdir(parents=True, exist_ok=True)
        stamp = datetime.fromtimestamp(self.clock(), timezone.utc).strftime("%Y%m%d-%H%M%S")
        path = d / f"{stamp}.cfg"
        n = 1
        while path.exists():
            path = d / f"{stamp}-{n}.cfg"
            n += 1
        path.write_text(cfg)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        self.audit.log("backup", device=device.name, file=path.name,
                       sha256=hashlib.sha256(cfg.encode()).hexdigest())
        return {"device": device.name, "file": path.name, "path": str(path), "bytes": len(cfg)}

    def diff(self, device_name: str, against: str = "latest") -> dict:
        device = self.inventory.get(device_name)
        d = self.home.backups_dir / device.name
        files = sorted(d.glob("*.cfg")) if d.exists() else []
        if against == "latest":
            if not files:
                raise NotFound("no backups for this device", hint=f"run `netmcp backup {device.name}` first")
            base = files[-1]
        else:
            base = d / os.path.basename(against)  # basename only: no path traversal
            if not base.exists():
                raise NotFound(f"no such backup '{against}'")
        with self._session(device) as (conn, drv):
            now = drv.get_config(conn)
        a, b = _normalize(device.family, base.read_text()), _normalize(device.family, now)
        diff = "\n".join(difflib.unified_diff(a, b, base.name, "current", lineterm=""))
        self.audit.log("diff", device=device.name, against=base.name, changed=bool(diff))
        return {"device": device.name, "against": base.name, "changed": bool(diff), "diff": redact(diff)}

    # ---------- changes ----------
    def plan(self, device_name: str, lines: list[str], note: str = "") -> dict:
        device = self.inventory.get(device_name)
        try:
            assessment = self.policy.assess(device.family, lines)
        except PolicyDenied as e:
            self.audit.log("plan_denied", device=device.name, lines=lines, reason=str(e))
            raise
        mode = self.policy.mode_for(device)
        needs = self.policy.needs_approval(assessment, mode)
        plan = self.plans.create(device.name, [l.line for l in assessment.lines], assessment.flags(), needs,
                                 mode, self.policy.data["plan_ttl_minutes"], note)
        self.audit.log("plan", plan_id=plan["plan_id"], device=device.name, mode=mode,
                       needs_approval=needs, lines=plan["lines"])
        return self._public(plan, needs)

    def _public(self, plan: dict, needs: bool) -> dict:
        hint = (f"approval required: ask the user to run `netmcp approve {plan['plan_id']}` in their own terminal, "
                f"then `netmcp apply {plan['plan_id']}`" if needs and plan["status"] != "approved"
                else f"run `netmcp apply {plan['plan_id']}`")
        return {"plan_id": plan["plan_id"], "device": plan["device"], "status": plan["status"],
                "mode": plan["mode_at_plan"], "needs_approval": needs, "lines": plan["lines"],
                "flags": plan["flags"], "expires_in_minutes": max(0, int((plan["expires"] - self.clock()) / 60)),
                "hint": hint}

    def _live_plan(self, plan_id: str) -> dict:
        plan = self.plans.load(plan_id)
        if plan["digest"] != digest(plan["device"], plan["lines"]):
            self.audit.log("plan_tampered", plan_id=plan_id)
            raise PolicyDenied("plan file was modified after creation", hint="create a new plan")
        if plan["status"] in ("applied", "failed"):
            raise PolicyDenied(f"plan already {plan['status']}", hint="create a new plan")
        if self.clock() > plan["expires"]:
            raise PolicyDenied("plan expired", hint="create a new plan")
        return plan

    def approve(self, plan_id: str, approver) -> dict:
        plan = self._live_plan(plan_id)
        summary = (f"Plan {plan_id} for device '{plan['device']}':\n"
                   + "\n".join(f"  {'!' if any(f['line'] == l for f in plan['flags']) else ' '} {l}" for l in plan["lines"])
                   + "\n('!' marks protected lines)")
        if not approver(summary):
            self.audit.log("approve_declined", plan_id=plan_id)
            raise ApprovalRequired("approval declined")
        plan["status"] = "approved"
        plan["approved_at"] = self.clock()
        plan["approved_via"] = getattr(approver, "via", "callback")
        self.plans.save(plan)
        self.audit.log("approve", plan_id=plan_id, via=plan["approved_via"])
        return self._public(plan, True)

    def apply(self, plan_id: str) -> dict:
        plan = self._live_plan(plan_id)
        device = self.inventory.get(plan["device"])
        # Re-assess with the CURRENT policy and mode: policy may have tightened since planning.
        assessment = self.policy.assess(device.family, plan["lines"])
        mode = self.policy.mode_for(device)
        if self.policy.needs_approval(assessment, mode) and plan["status"] != "approved":
            self.audit.log("apply_blocked", plan_id=plan_id, reason="approval required")
            raise ApprovalRequired(f"plan {plan_id} needs human approval in '{mode}' mode",
                                   hint=f"ask the user to run `netmcp approve {plan_id}` in their own terminal")
        minutes = self.policy.data["rollback_minutes"]
        lines = plan["lines"]
        self.audit.log("apply_start", plan_id=plan_id, device=device.name, mode=mode, lines=lines)

        # Phase 1: backup -> arm rollback -> apply. Rollback must be confirmed armed before anything changes.
        try:
            with self._session(device) as (conn, drv):
                pre = drv.get_config(conn)
                backup = self._store_backup(device, pre)
                token = drv.arm_rollback(conn, minutes)
                try:
                    drv.apply(conn, lines)
                except NetmcpError as e:
                    e.hint = (f"changes may be partially applied; the rollback timer is armed and the device will "
                              f"revert in about {minutes} minutes")
                    raise
        except NetmcpError as e:
            self._finish(plan, "failed", f"{e.code}: {e}")
            raise

        # Phase 2: fresh connection proves management access still works, then disarm + persist.
        try:
            with self._session(device) as (conn, drv):
                drv.heartbeat(conn)
                for chk in device.verify:
                    cmd = self.policy.check_read(device.family, drv.normalize_read(chk["cmd"]))
                    out, _ = drv.show(conn, cmd, parse=False)
                    if chk.get("contains", "").lower() not in str(out).lower():
                        raise VerifyFailed(f"verify check failed: '{cmd}' output lacks '{chk.get('contains')}'")
                drv.disarm_rollback(conn, token)
                saved = drv.persist(conn)
                post = drv.get_config(conn)
        except NetmcpError as e:
            msg = (f"post-change verification failed ({e}). The rollback timer was left armed: the device should "
                   f"revert within about {minutes} minutes. Do not cancel it unless you have confirmed access.")
            self._finish(plan, "failed", msg)
            raise VerifyFailed(msg, hint="wait for the rollback, then investigate; re-plan a smaller change") from e

        a, b = _normalize(device.family, pre), _normalize(device.family, post)
        diff = "\n".join(difflib.unified_diff(a, b, "before", "after", lineterm=""))
        self._finish(plan, "applied", "ok")
        return {"plan_id": plan_id, "device": device.name, "applied": True, "verified": True,
                "saved_to_startup": saved, "backup": backup["file"], "rollback": "disarmed",
                "diff": redact(diff)}

    def _finish(self, plan: dict, status: str, detail: str) -> None:
        plan["status"] = status
        self.plans.save(plan)
        self.audit.log("apply_" + ("ok" if status == "applied" else "failed"), plan_id=plan["plan_id"], detail=detail)

    # ---------- mode ----------
    def mode_info(self) -> dict:
        return {"mode": self.policy.mode, "modes": list(MODES)}

    def set_mode(self, new_mode: str, approver=None) -> dict:
        if new_mode not in MODES:
            raise PolicyDenied(f"mode must be one of {MODES}")
        loosening = MODES.index(new_mode) > MODES.index(self.policy.mode)
        if loosening:
            if approver is None or not approver(f"Change approval mode: {self.policy.mode} -> {new_mode}"):
                raise ApprovalRequired("loosening the approval mode needs human approval",
                                       hint="ask the user to run `netmcp mode set <mode>` in their own terminal")
        old = self.policy.mode
        self.policy.write_mode(new_mode)
        self.audit.log("mode_change", old=old, new=new_mode)
        return {"mode": new_mode, "previous": old}
