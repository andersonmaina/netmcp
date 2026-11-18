# netmcp

Let AI agents (Claude Code, Antigravity, Hermes, anything that can run a shell command or speak MCP) work with **Cisco IOS/IOS-XE/NX-OS** and **MikroTik RouterOS** devices, without handing them an unguarded SSH session.

Built on [Netmiko](https://github.com/ktbyers/netmiko). Reads are easy. Changes go through a plan → approve → apply pipeline with a backup, a device-side rollback timer, and post-change verification.

> **Status: 0.1, pre-release.** The safety pipeline is covered by unit tests against fake devices. The rollback mechanisms (`reload in` on Cisco, a scheduler-restore on MikroTik) still need validation against real or virtual devices; see `tests/integration/`. Do not point this at production gear until you have run those.

## Install

```bash
pip install netmcp            # CLI
pip install "netmcp[mcp]"     # + MCP server
netmcp init                   # creates ~/.netmcp with a sample inventory.yaml and policy.yaml
```

Credentials are never stored in the inventory. Use env vars (`NETMCP_<DEVICE>_PASSWORD`, `NETMCP_<DEVICE>_SECRET`) or the OS keyring (`pip install keyring`, then `python -m keyring set netmcp <device>`).

## CLI

Every command prints one JSON envelope: `{"ok": true, "data": ...}` or `{"ok": false, "error": {"code", "message", "hint"}}`.

| Exit | Meaning |
|---|---|
| 0 | ok |
| 2 | denied by policy |
| 3 | human approval required |
| 4 | connection failed |
| 5 | device error / verification failed |
| 6 | not found |

```bash
netmcp inventory list
netmcp show r1 "show ip interface brief" "show ip route"     # Cisco: parsed via TextFSM when a template exists
netmcp show mt1 "/ip address print" "/interface print"       # MikroTik: print output parsed to rows
netmcp backup r1
netmcp diff r1                                               # current vs latest backup
netmcp health r1

netmcp plan r1 --line "interface Gi0/1" --line "description uplink"   # validates only, touches nothing
netmcp approve p_1a2b3c4d                                    # HUMAN: prompts on your terminal
netmcp apply p_1a2b3c4d

netmcp mode show
netmcp mode set autonomous                                   # HUMAN: loosening asks on your terminal
netmcp serve                                                 # MCP server over stdio
```

## Approval modes

| Mode | Reads | Changes |
|---|---|---|
| `strict` (default) | auto | every plan needs `netmcp approve` |
| `supervised` | auto | low-risk lines (descriptions/comments) auto-apply; everything else needs approval |
| `autonomous` | auto | the agent plans and applies on its own |

Hard-deny rules, the backup, the rollback timer, and verification apply **in every mode**, including `autonomous`. Per-device override: `mode:` in `inventory.yaml`.

## What happens on `apply`

1. Re-check the plan against the *current* policy and mode (a tightened policy blocks old plans).
2. Back up the config locally.
3. Arm a device-side rollback timer and **confirm it is armed**. If that can't be confirmed, nothing is changed.
   - Cisco: `reload in N` (nothing is saved until verification passes, so the reboot lands on the last saved config).
   - MikroTik: binary backup + a one-shot scheduler that restores it.
4. Apply the lines. The device rejecting a command aborts the run and leaves the timer armed.
5. Open a **fresh** SSH session (proves management access survived), run the heartbeat and any `verify:` checks from the inventory.
6. Only then: cancel the timer and save to startup-config (Cisco). If step 5 fails, the timer is left armed and the device reverts by itself.

## Policy

`~/.netmcp/policy.yaml`. Lists you add to `hard_deny` and `protected.patterns` are **appended** to the built-in defaults; you cannot accidentally remove a default. Declare your management interfaces under `protected.interfaces` so changes touching them always need approval outside `autonomous`.

Matching is token- and abbreviation-aware (`rel` is caught as `reload`, `/sys reb` as `/system reboot`) and covers RouterOS `[ ... ]` sub-expressions. It is deliberately conservative, but pattern-based checks are best-effort. **The rollback timer is the real safety net.**

## Threat model (read this)

netmcp narrows what an agent can do through *its* interface. It cannot stop an agent that has the same OS user and credentials from bypassing it (running Netmiko directly, editing `~/.netmcp`, flipping the mode file).

- Approval is asked on the controlling terminal (`/dev/tty` / `CONIN$`). An agent's subprocess normally has none, so it cannot approve its own plans.
- **The real boundary is credentials.** Run `netmcp serve` as the only process that holds device passwords, and give the agent MCP access only. The MCP server deliberately exposes **no approve and no mode-change tools**.
- If you run the CLI in the agent's own shell, also add deny rules in the agent's permission system for `netmcp approve` and `netmcp mode set`, and keep device passwords out of the agent's environment.
- Output is redacted (passwords, secrets, SNMP communities, pre-shared keys) before it reaches the agent or the audit log (`~/.netmcp/state/audit.jsonl`). Local backups are stored unredacted so they stay restorable; they are mode 0600.

## Telling your agent how to use it

Drop this in `AGENTS.md` / `CLAUDE.md`:

```
Use `netmcp` for all router work; never SSH to devices directly.
- Read with `netmcp show <device> "<cmd>"`. Prefer structured output.
- To change anything: `netmcp plan`, show the user the plan, then `netmcp apply`.
- If apply exits 3, ask the user to run `netmcp approve <plan_id>` in their own terminal. Never try to approve or change the mode yourself.
- After a failed verification the device rolls itself back in a few minutes. Do not cancel the timer; wait and re-plan a smaller change.
```

## Development

```bash
pip install -e ".[dev,mcp]"
pytest                      # unit + fake-device tests
NETMCP_LAB_HOME=... NETMCP_LAB_DEVICES=cisco-lab,chr-lab pytest -m integration
```

For lab devices: MikroTik **CHR** (free, runs in VirtualBox/QEMU/GNS3), Cisco **CML** or GNS3/EVE-NG with IOSv.

## License

MIT
