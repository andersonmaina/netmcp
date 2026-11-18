from __future__ import annotations

from .errors import NetmcpError


def run(fn):
    """Run fn and wrap the outcome in the JSON envelope shared by the CLI and the MCP server."""
    try:
        return {"ok": True, "data": fn()}, 0
    except NetmcpError as e:
        return {"ok": False, "error": {"code": e.code, "message": str(e), "hint": e.hint}}, e.exit_code
    except Exception as e:  # noqa: BLE001 - never leak a traceback to an agent
        return {"ok": False, "error": {"code": "internal_error", "message": f"{type(e).__name__}: {e}", "hint": None}}, 1
