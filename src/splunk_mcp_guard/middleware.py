"""The guard itself: a FastMCP middleware.

Order of operations for every tool call:

    identity  →  policy class  →  (inspect | approve)  →  forward  →  output guard  →  audit

Denied tools are also removed from ``tools/list`` for that principal, so the
model does not even see them.  Hiding is convenience; blocking in
``on_call_tool`` is the actual control.
"""

from __future__ import annotations

import time
from typing import Any

import mcp.types as mt
from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools import ToolResult

from .approval import request_approval
from .audit import AuditLog
from .identity import resolve_principal
from .output_guard import OutputGuard
from .policy import Policy, ToolClass
from .spl_inspector import SplInspector


class GuardMiddleware(Middleware):
    def __init__(self, policy: Policy, audit: AuditLog, inspector: SplInspector, output: OutputGuard):
        self.policy = policy
        self.audit = audit
        self.inspector = inspector
        self.output = output

    # ------------------------------------------------------------ listing

    async def on_list_tools(self, context: MiddlewareContext[Any], call_next: CallNext[Any, Any]):
        tools = await call_next(context)
        principal = resolve_principal(self.policy.identity)
        role = self.policy.role_for(principal)
        visible = []
        for t in tools:
            name = getattr(t, "name", None) or getattr(t, "key", None)
            if name is None:
                continue
            if self.policy.classify(role, name) is not ToolClass.DENY:
                visible.append(t)
        return visible

    # ------------------------------------------------------------ calling

    async def on_call_tool(
        self,
        context: MiddlewareContext[mt.CallToolRequestParams],
        call_next: CallNext[mt.CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        t0 = time.perf_counter()
        tool = context.message.name
        args: dict[str, Any] = dict(context.message.arguments or {})
        principal = resolve_principal(self.policy.identity)
        role = self.policy.role_for(principal)
        cls = self.policy.classify(role, tool)

        if cls is ToolClass.DENY:
            self.audit.decision(principal=principal, role=role.name, tool=tool, decision="deny",
                                reason="tool denied by policy", args=args)
            raise ToolError(f"[guard] '{tool}' is not permitted for principal '{principal}'.")

        notes: list[str] = []
        if cls is ToolClass.INSPECT:
            reasons: list[str] = []
            spl_seen = False
            for key in self.policy.spl_args_for(role, tool):
                val = args.get(key)
                if not isinstance(val, str) or not val.strip():
                    continue
                spl_seen = True
                ins = await self.inspector.inspect(
                    val,
                    earliest=args.get("earliest_time") or args.get("earliest"),
                    latest=args.get("latest_time") or args.get("latest"),
                    count=_as_int(args.get("count") or args.get("max_results")),
                    allowed_indexes=role.indexes,
                )
                if not ins.ok:
                    reasons.extend(ins.reasons)
                elif ins.reasons:
                    # advisory only (e.g. parser unavailable, absolute time not enforced)
                    notes.extend(ins.reasons)
                notes.append(f"commands={sorted(ins.commands)} parser={ins.parser_used}")
            if not spl_seen:
                # an inspect-class tool with no SPL argument: treat as suspicious
                reasons.append("inspect-class tool called without an SPL argument")
            if reasons:
                self.audit.decision(principal=principal, role=role.name, tool=tool,
                                    decision="inspect-deny", reason="; ".join(reasons), args=args)
                raise ToolError("[guard] search rejected: " + "; ".join(reasons))

        if cls is ToolClass.APPROVE:
            ok, detail = await request_approval(
                context.fastmcp_context, principal=principal, tool=tool, args=args
            )
            if not ok:
                self.audit.decision(principal=principal, role=role.name, tool=tool,
                                    decision="approve-deny", reason=detail, args=args)
                raise ToolError(f"[guard] '{tool}' requires human approval: {detail}")

        # ---- forward to the real server
        try:
            result = await call_next(context)
        except Exception as e:
            self.audit.error(principal, tool, f"{e.__class__.__name__}: {e}")
            raise

        # ---- output guard
        result, rep_hits, rep_redactions, raw_text = self._guard_result(result)

        self.audit.decision(
            principal=principal, role=role.name, tool=tool,
            decision={ToolClass.ALLOW: "allow", ToolClass.INSPECT: "inspect-ok",
                      ToolClass.APPROVE: "approve-ok"}[cls],
            args=args, result_text=raw_text,
            duration_ms=round((time.perf_counter() - t0) * 1000, 1),
            injection_hits=rep_hits, redactions=rep_redactions, notes=notes,
        )
        return result

    # ------------------------------------------------------------ helpers

    def _guard_result(self, result: ToolResult):
        hits: list[str] = []
        redactions = 0
        raw_parts: list[str] = []
        new_content = []
        for block in list(result.content or []):
            if isinstance(block, mt.TextContent):
                raw_parts.append(block.text)
                rep = self.output.process(block.text)
                hits.extend(rep.injection_hits)
                redactions += rep.redactions
                new_content.append(mt.TextContent(type="text", text=rep.text))
            else:
                new_content.append(block)

        structured = result.structured_content
        if structured is not None:
            structured, s_red, s_hits = self.output.process_structured(structured)
            redactions += s_red
            # the same finding usually appears in both channels; keep it once
            hits.extend(h for h in s_hits if h not in hits)

        guarded = ToolResult(content=new_content, structured_content=structured,
                             meta=getattr(result, "meta", None), is_error=getattr(result, "is_error", False))
        return guarded, hits, redactions, "\n".join(raw_parts)


def _as_int(v: Any) -> int | None:
    try:
        return int(v) if v is not None else None
    except (TypeError, ValueError):
        return None
