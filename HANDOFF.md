# netmcp: handoff

## What this is
`netmcp` is a publishable Python tool (CLI + MCP server, built on Netmiko) that lets AI agents work with **Cisco (IOS/IOS-XE)** and **MikroTik RouterOS** devices safely: VLANs, IPs, routes, DHCP, etc. The safety layer is the product. Reads are free; changes go through plan → approve → apply with backup, a device-side rollback timer, and post-change verification.

Owner: Anderson (CCNA-level, Python/TS dev). He wants it open-sourced (MIT) and he wants an approval toggle: approve everything, or let the agent act on its own. Keep replies direct and concise.

## Current state: v0.1.0, code complete, NOT validated on real devices
- 106 unit tests pass, 1 skipped (the lab integration test). Run: `pip install -e ".[dev,mcp]" && pytest`
- Everything is tested against in-memory fakes (`tests/fakes.py`). **No real or virtual router has been touched yet.**
- `mcp` is pinned `<2` because mcp 2.x renamed `FastMCP` to `MCPServer`. Supporting both is a small TODO.

## Layout
```
src/netmcp/
  cli.py          argparse CLI, JSON envelope output, exit codes (0 ok, 2 denied, 3 approval needed, 4 conn, 5 device/verify, 6 not found)
  api.py          run(fn) -> envelope; shared by CLI and MCP
  runtime.py      the pipeline: show/backup/diff/health/plan/approve/apply/set_mode
  policy.py       hard-deny, protected, low-risk, modes, read allowlists
  drivers/        base.py, cisco.py, mikrotik.py (vendor logic: config fetch, parsing, rollback arm/disarm, persist)
  plans.py        plan store (JSON, sha256 digest, TTL)
  approval.py     tty approver (/dev/tty or CONIN$/CONOUT$)
  inventory.py    devices + credentials (env vars or keyring; passwords in inventory are rejected)
  audit.py        append-only JSONL, redacted
  redact.py       secret redaction (Cisco + RouterOS styles)
  mcp_server.py   7 tools; deliberately NO approve and NO mode-change tool
tests/            fakes.py (FakeNet), test_policy/pipeline/cli/misc, integration/test_lab.py (opt-in, -m integration)
```

## Design decisions (don't undo without asking Anderson)
- **Modes:** `strict` (default; every change needs approval), `supervised` (low-risk lines auto-apply), `autonomous`. Hard-deny, backup, rollback and verify apply in ALL modes. Loosening the mode needs a human via tty; tightening doesn't. Per-device `mode:` override in inventory.
- **Approval can't be self-granted by an agent** because it prompts on the controlling TTY, which agent subprocesses normally lack. MCP server exposes no approve/mode tools.
- **Policy lists only extend defaults** (`hard_deny`, `protected.patterns`, etc. are appended, never replaced).
- **Matching is token + abbreviation aware** (`rel` is caught as `reload`, `/sys reb` as `/system reboot`) and checks RouterOS `[ ... ]` sub-expressions. MikroTik lines must be absolute (`/...`) with no `; { }`. It over-denies rather than under-denies.
- **Apply pipeline:** re-assess against current policy → backup → arm rollback and CONFIRM it is armed (else abort, nothing changed) → apply → open a FRESH session → heartbeat + inventory `verify:` checks → disarm rollback → persist (Cisco `write memory`). If verification fails, the timer is left armed so the device reverts itself.
- **Rollback mechanisms:** Cisco `reload in N` (never saves as a side effect). MikroTik: `/system backup save` + one-shot scheduler that runs `/system backup load`.
- `plan` is offline (no device connection). The real diff is returned after `apply`.
- Output and audit are redacted. Local backups are stored unredacted (mode 0600) so they stay restorable.
- Rule for contributors: vendor-specific behavior goes in `drivers/`, never in `runtime.py` or `policy.py`.

## Unverified assumptions (the first thing to test on real/virtual gear)
**Cisco**
- `reload in N` prompt sequence (`Save? [yes/no]`, `Proceed with reload? [confirm]`) and the `show reload` strings (`Reload scheduled`, `No reload is scheduled`) in `drivers/cisco.py`.
- `reload cancel` really clears it.
- On older IOS switches, VLAN DB changes (`vlan.dat`) may NOT be reverted by the reload.
- Netmiko TextFSM parsing via `use_textfsm=True`.

**MikroTik**
- `start-time=([/system clock get time]+HH:MM:00)` expression in the scheduler. Midnight wrap is unhandled.
- `/system backup save ... dont-encrypt=yes` and `/system backup load name=netmcp-pre` working non-interactively from a scheduler.
- `/export hide-sensitive terse`, `/file remove [find name~"netmcp-pre"]`.
- Netmiko `mikrotik_routeros` quirks: output width, `send_config_set` behavior, error regex in `MikroTikDriver.error_re`.

**Other**
- Windows tty approval (`CONIN$`/`CONOUT$`) is untested.

## Known gaps / bugs to fix
1. **`cisco_nxos` is listed in `inventory.VENDORS` but uses the IOS driver. NX-OS has no `reload in`.** Either remove it until implemented or implement checkpoint/`configure session` rollback.
2. No manual `rollback` command yet.
3. On verify failure with SSH still working, we just wait for the timer. Consider immediate rollback.
4. No config-drift check between `plan` and `apply` (plans only expire after 30 min).
5. Plan approval status lives in a plain JSON file, so same-user tampering is possible (documented in README). Consider an HMAC or keeping state in the MCP process.
6. Evaluate Cisco `configure terminal revert timer` + `configure confirm` as a gentler rollback than a reboot.
7. MikroTik `health` and parsed-output coverage is thin. `diff` ignores secret changes because exports hide sensitive values.
8. Support both mcp v1 `FastMCP` and v2 `MCPServer`. Consider MCP elicitation as an optional approval path.
9. No CI, no CHANGELOG, PyPI name `netmcp` availability unchecked.

## Next steps, in order
1. Stand up a lab: MikroTik **CHR** (VirtualBox/QEMU/GNS3) and Cisco **IOSv** (CML or GNS3/EVE-NG). Put device names in an inventory, set `NETMCP_<NAME>_PASSWORD`, mark the management interface under `protected.interfaces`.
2. Run `NETMCP_LAB_HOME=... NETMCP_LAB_DEVICES=... pytest -m integration`. The key test (`test_lockout_rolls_back_by_itself`) shuts the management interface and expects the device to recover on its own. Adjust interface names in `SHUTDOWN_MGMT`.
3. Fix whatever breaks in `arm_rollback`/`disarm_rollback` for each vendor; add fake-device tests that reproduce each fix.
4. Resolve gap #1 (NX-OS), then #2 and #3.
5. GitHub Actions (pytest on 3.10–3.13), then PyPI release as 0.1.x.
6. Real-world task tests via an agent: create a VLAN, set IPs, add a route on both vendors.

## Rules while working on it
- Never weaken defaults (`strict` mode, hard-deny list, rollback-must-confirm-armed).
- Never log or return secrets. Add a redaction test for any new output path.
- Every change to the apply pipeline needs a fake-device test, including its failure paths.
- Keep the JSON envelope and exit codes stable (agents depend on them).
