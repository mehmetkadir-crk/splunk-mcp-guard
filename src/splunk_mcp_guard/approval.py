"""Human approval for write-class tools.

Two ways to reach a person, both fail closed:

1. MCP elicitation: the client shows the person a prompt. Many clients do not
   support it yet (Claude Desktop answers "Method not found").
2. Approval directory: the guard writes <dir>/<id>.request.json and waits for
   `splunk-mcp-guard approve <id>` (or reject) from a terminal.

Whoever can write to the approval directory is the approver, so it must not be
writable by the assistant's own tools. In `auto` mode the directory is used
only when the client cannot elicit; a "no" given through the client is final.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import secrets
import time
from pathlib import Path
from typing import Any

from fastmcp.server.elicitation import AcceptedElicitation

from .policy import ApprovalPolicy

_ID = re.compile(r"\d+-[0-9a-f]{6}")
_ELICIT_UNSUPPORTED_MARKERS = ("method not found", "not supported", "unsupported", "-32601")


def _preview(args: dict[str, Any], spl_keys: list[str] | None = None) -> str:
    # SPL arguments first and in full, so padding in other fields cannot hide them
    spl_keys = [k for k in (spl_keys or []) if k in args]
    lines = [f"{k}: {args[k]}" for k in spl_keys]
    for k, v in args.items():
        if k in spl_keys:
            continue
        text = json.dumps(v, ensure_ascii=False, default=str)
        lines.append(f"{k}: {text if len(text) <= 300 else text[:300] + ' ...'}")
    return "\n".join(lines)


async def _elicit(ctx: Any, *, principal: str, tool: str, args: dict[str, Any],
                  spl_keys: list[str] | None) -> tuple[bool | None, str]:
    """Return (approved, detail); approved is None when the client cannot elicit."""
    if ctx is None:
        return None, "no request context"
    message = (
        f"[splunk-mcp-guard] Approval required.\n"
        f"Principal: {principal}\nTool: {tool}\n{_preview(args, spl_keys)}\n\n"
        f"This tool changes Splunk state. Approve?"
    )
    try:
        result = await ctx.elicit(message, response_type=["approve", "reject"])
    except Exception as e:
        msg = f"{e.__class__.__name__}: {e}"
        if any(m in msg.lower() for m in _ELICIT_UNSUPPORTED_MARKERS):
            return None, f"client does not support elicitation ({msg})"
        return False, f"elicitation failed: {msg}"

    if isinstance(result, AcceptedElicitation):
        choice = result.data
        if isinstance(choice, dict):
            choice = choice.get("value") or choice.get("choice") or next(iter(choice.values()), None)
        if str(choice).lower() == "approve":
            return True, "approved by human (elicitation)"
        return False, f"human chose {choice!r}"
    return False, f"elicitation {result.__class__.__name__.replace('Elicitation', '').lower()}"


def _request_path(d: Path, rid: str) -> Path:
    return d / f"{rid}.request.json"


def _decision_path(d: Path, rid: str) -> Path:
    return d / f"{rid}.decision.json"


async def _wait_for_file_decision(
    pol: ApprovalPolicy, *, principal: str, tool: str, args: dict[str, Any]
) -> tuple[bool, str]:
    d = Path(pol.dir)
    try:
        d.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            os.chmod(d, 0o700)
    except OSError as e:
        return False, f"approval dir unusable: {e}"

    rid = f"{int(time.time())}-{secrets.token_hex(3)}"
    req = {
        "id": rid, "created": time.time(), "principal": principal, "tool": tool,
        "args": args, "expires": time.time() + pol.timeout_seconds,
        "how": f"splunk-mcp-guard approve {rid}   |   splunk-mcp-guard reject {rid}",
    }
    rp, dp = _request_path(d, rid), _decision_path(d, rid)
    rp.write_text(json.dumps(req, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    if os.name != "nt":
        os.chmod(rp, 0o600)

    deadline = time.monotonic() + pol.timeout_seconds
    try:
        while time.monotonic() < deadline:
            if dp.exists():
                try:
                    dec = json.loads(dp.read_text(encoding="utf-8"))
                except (OSError, ValueError) as e:
                    return False, f"unreadable decision file: {e}"
                if dec.get("id") != rid:
                    return False, "decision file does not match request id"
                who = dec.get("by") or "unknown"
                if dec.get("decision") == "approve":
                    return True, f"approved out-of-band by {who} (id {rid})"
                return False, f"rejected out-of-band by {who} (id {rid})"
            await asyncio.sleep(pol.poll_seconds)
        return False, f"no decision within {pol.timeout_seconds}s (id {rid})"
    finally:
        for p in (rp, dp):
            try:
                p.unlink()
            except OSError:
                pass


async def request_approval(
    ctx: Any, *, principal: str, tool: str, args: dict[str, Any],
    policy: ApprovalPolicy | None = None, spl_keys: list[str] | None = None,
) -> tuple[bool, str]:
    """Return (approved, detail). Anything but an explicit yes is a no.

    `args` should already be redacted; they are shown to a person and written
    to the approval directory.
    """
    pol = policy or ApprovalPolicy(mode="elicit")

    if pol.mode in {"elicit", "auto"}:
        ok, detail = await _elicit(ctx, principal=principal, tool=tool, args=args, spl_keys=spl_keys)
        if ok is not None:
            return ok, detail
        if pol.mode == "elicit":
            return False, detail
        fallback_note = detail
    else:
        fallback_note = "mode=file"

    ok, detail = await _wait_for_file_decision(pol, principal=principal, tool=tool, args=args)
    return ok, f"{detail}; {fallback_note}"


def list_pending(dir_: str) -> list[dict[str, Any]]:
    d = Path(dir_)
    out: list[dict[str, Any]] = []
    if not d.is_dir():
        return out
    for rp in sorted(d.glob("*.request.json")):
        try:
            req = json.loads(rp.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        req["expired"] = time.time() > float(req.get("expires", 0))
        out.append(req)
    return out


def decide(dir_: str, rid: str, decision: str, by: str | None = None) -> str:
    """Write a decision file for *rid* and return a one-line status."""
    if not _ID.fullmatch(rid or ""):
        return f"invalid request id {rid!r}"
    d = Path(dir_)
    rp = _request_path(d, rid)
    if not rp.exists():
        return f"no pending request with id {rid}"
    try:
        req = json.loads(rp.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        return f"cannot read request: {e}"
    if time.time() > float(req.get("expires", 0)):
        return f"request {rid} already expired"
    who = by or os.environ.get("USERNAME") or os.environ.get("USER") or "human"
    _decision_path(d, rid).write_text(
        json.dumps({"id": rid, "decision": decision, "by": who, "at": time.time()}), encoding="utf-8"
    )
    return f"{decision}: {req.get('tool')} for {req.get('principal')} (id {rid}) by {who}"
