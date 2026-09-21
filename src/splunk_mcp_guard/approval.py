"""Human approval for write-class tools, via MCP elicitation.

The server asks the *client* to ask the *human*.  If the client does not
support elicitation, or the human declines, cancels, or times out, the answer
is "no".  Fail closed, always.
"""

from __future__ import annotations

import json
from typing import Any

from fastmcp.server.elicitation import AcceptedElicitation


async def request_approval(ctx: Any, *, principal: str, tool: str, args: dict[str, Any]) -> tuple[bool, str]:
    """Return (approved, detail)."""
    if ctx is None:
        return False, "no request context; cannot ask for approval"

    preview = json.dumps(args, ensure_ascii=False, default=str)
    if len(preview) > 1500:
        preview = preview[:1500] + " …"
    message = (
        f"[splunk-mcp-guard] Approval required.\n"
        f"Principal: {principal}\n"
        f"Tool: {tool}\n"
        f"Arguments: {preview}\n\n"
        f"This tool changes Splunk state. Approve?"
    )
    try:
        result = await ctx.elicit(message, response_type=["approve", "reject"])
    except Exception as e:  # client lacks elicitation, transport error, etc.
        return False, f"elicitation failed: {e.__class__.__name__}: {e}"

    if isinstance(result, AcceptedElicitation):
        choice = result.data
        if isinstance(choice, dict):
            choice = choice.get("value") or choice.get("choice") or next(iter(choice.values()), None)
        if str(choice).lower() == "approve":
            return True, "approved by human"
        return False, f"human chose {choice!r}"
    return False, f"elicitation {result.__class__.__name__.replace('Elicitation', '').lower()}"
