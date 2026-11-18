"""MCP server. Deliberately exposes NO approve and NO mode-change tools: approval stays with the human."""
from __future__ import annotations

from .api import run
from .runtime import Runtime


def build_server(runtime: Runtime | None = None):
    from mcp.server.fastmcp import FastMCP

    rt = runtime or Runtime()
    mcp = FastMCP("netmcp")

    @mcp.tool()
    def list_devices() -> dict:
        """List devices in the inventory (names, vendor, approval mode). No credentials are ever shown."""
        return run(rt.inventory_list)[0]

    @mcp.tool()
    def show(device: str, commands: list[str], parse: bool = True) -> dict:
        """Run read-only commands (Cisco: show/ping/traceroute; MikroTik: print/export/get/ping). Returns structured data when possible."""
        return run(lambda: rt.show(device, commands, parse))[0]

    @mcp.tool()
    def health(device: str) -> dict:
        """Quick health snapshot of a device."""
        return run(lambda: rt.health(device))[0]

    @mcp.tool()
    def backup(device: str) -> dict:
        """Save the current config locally."""
        return run(lambda: rt.backup(device))[0]

    @mcp.tool()
    def diff(device: str, against: str = "latest") -> dict:
        """Diff the current config against a saved backup."""
        return run(lambda: rt.diff(device, against))[0]

    @mcp.tool()
    def plan_change(device: str, lines: list[str], note: str = "") -> dict:
        """Validate a config change against policy and create a plan. Touches nothing on the device."""
        return run(lambda: rt.plan(device, lines, note))[0]

    @mcp.tool()
    def apply_plan(plan_id: str) -> dict:
        """Apply a plan (backup, rollback timer, apply, verify). May require human approval depending on mode."""
        return run(lambda: rt.apply(plan_id))[0]

    return mcp


def main() -> None:
    build_server().run()
