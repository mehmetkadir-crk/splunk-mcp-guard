"""FastMCP middleware that enforces the policy.

For every tool call: identity -> role -> tool class -> SPL inspection and/or
human approval -> forward -> output guard -> audit. Denied tools are also left
out of tools/list. Resources and prompts from the backend are denied unless the
policy allows them, because they would bypass the tool rules.
"""

from __future__ import annotations

import time
from typing import Any

import mcp.types as mt
from fastmcp.exceptions import PromptError, ResourceError, ToolError
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools import ToolResult

from .approval import request_approval
from .audit import AuditLog
from .identity import resolve_principal
from .output_guard import OutputGuard
from .policy import Policy, PolicyError, RolePolicy, ToolClass
from .spl_inspector import SplInspector


class GuardMiddleware(Middleware):
    def __init__(self, policy: Policy, audit: AuditLog, inspector: SplInspector, output: OutputGuard):
        self.policy = policy
        self.audit = audit
        self.inspector = inspector
        self.output = output

    def _who(self) -> tuple[str | None, RolePolicy | None]:
        principal = resolve_principal(self.policy.identity)
        if principal is None:
            return None, None
        try:
            return principal, self.policy.role_for(principal)
        except PolicyError:
            return principal, None


    async def on_list_tools(self, context: MiddlewareContext[Any], call_next: CallNext[Any, Any]):
        tools = await call_next(context)
        _, role = self._who()
        if role is None:
            return []
        return [t for t in tools
                if (name := getattr(t, "name", None) or getattr(t, "key", None)) is not None
                and self.policy.classify(role, name) is not ToolClass.DENY]

    async def on_call_tool(
        self,
        context: MiddlewareContext[mt.CallToolRequestParams],
        call_next: CallNext[mt.CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        t0 = time.perf_counter()
        tool = context.message.name
        args: dict[str, Any] = dict(context.message.arguments or {})
        principal, role = self._who()

        if principal is None or role is None:
            who = principal or "unauthenticated"
            self.audit.decision(principal=who, role=None, tool=tool, decision="deny",
                                reason="no valid principal or role", args=args)
            raise ToolError("[guard] request denied: caller could not be identified.")

        cls = self.policy.classify(role, tool)

        if cls is ToolClass.DENY:
            self.audit.decision(principal=principal, role=role.name, tool=tool, decision="deny",
                                reason="tool denied by policy", args=args)
            raise ToolError(f"[guard] '{tool}' is not permitted for principal '{principal}'.")

        notes: list[str] = []
        spl_keys = [k for k in self.policy.spl_args_for(role, tool)
                    if isinstance(args.get(k), str) and args[k].strip()]
        if cls in (ToolClass.INSPECT, ToolClass.APPROVE):
            reasons: list[str] = []
            if cls is ToolClass.INSPECT and not spl_keys:
                reasons.append("inspect-class tool called without an SPL argument")
            counts = [args[k] for k in ("count", "max_results") if args.get(k) is not None]
            for key in spl_keys:
                try:
                    ins = await self.inspector.inspect(
                        args[key],
                        earliest=args.get("earliest_time") or args.get("earliest"),
                        latest=args.get("latest_time") or args.get("latest"),
                        count=counts or None,
                        allowed_indexes=role.indexes,
                    )
                except Exception as e:
                    reasons.append(f"inspection failed: {e.__class__.__name__}: {e}")
                    continue
                if not ins.ok:
                    reasons.extend(ins.reasons)
                elif ins.reasons:
                    notes.extend(ins.reasons)
                notes.append(f"{key}: commands={sorted(ins.commands)} parser={ins.parser_used}")
            if reasons:
                decision = "inspect-deny" if cls is ToolClass.INSPECT else "approve-deny"
                self.audit.decision(principal=principal, role=role.name, tool=tool,
                                    decision=decision, reason="; ".join(reasons), args=args)
                raise ToolError("[guard] search rejected: " + "; ".join(reasons))

        if cls is ToolClass.APPROVE:
            ok, detail = await request_approval(
                context.fastmcp_context, principal=principal, tool=tool,
                args=self.audit.redact(args), policy=self.policy.approval, spl_keys=spl_keys,
            )
            if not ok:
                self.audit.decision(principal=principal, role=role.name, tool=tool,
                                    decision="approve-deny", reason=detail, args=args)
                raise ToolError(f"[guard] '{tool}' requires human approval: {detail}")
            notes.append(detail)

        try:
            result = await call_next(context)
        except BaseException as e:
            self.audit.error(principal, tool, f"{e.__class__.__name__}: {e} (after forwarding)")
            raise

        result, hits, redactions, raw_text = self._guard_result(result)
        self.audit.decision(
            principal=principal, role=role.name, tool=tool,
            decision={ToolClass.ALLOW: "allow", ToolClass.INSPECT: "inspect-ok",
                      ToolClass.APPROVE: "approve-ok"}[cls],
            args=args, result_text=raw_text,
            duration_ms=round((time.perf_counter() - t0) * 1000, 1),
            injection_hits=hits, redactions=redactions, notes=notes,
        )
        return result

    def _guard_result(self, result: ToolResult):
        hits: list[str] = []
        redactions = 0
        raw_parts: list[str] = []
        new_content: list[Any] = []
        for block in list(result.content or []):
            if isinstance(block, mt.TextContent):
                raw_parts.append(block.text)
                rep = self.output.process(block.text)
                hits.extend(rep.injection_hits)
                redactions += rep.redactions
                new_content.append(mt.TextContent(type="text", text=rep.text))
            elif isinstance(block, mt.EmbeddedResource) and isinstance(block.resource, mt.TextResourceContents):
                raw_parts.append(block.resource.text)
                rep = self.output.process(block.resource.text)
                hits.extend(rep.injection_hits)
                redactions += rep.redactions
                res = block.resource.model_copy(update={"text": rep.text})
                new_content.append(block.model_copy(update={"resource": res}))
            else:
                new_content.append(block)

        structured = result.structured_content
        if structured is not None:
            structured, s_red, s_hits = self.output.process_structured(structured)
            redactions += s_red
            hits.extend(h for h in s_hits if h not in hits)

        guarded = ToolResult(content=new_content, structured_content=structured,
                             meta=getattr(result, "meta", None), is_error=getattr(result, "is_error", False))
        return guarded, hits, redactions, "\n".join(raw_parts)


    def _extras_allowed(self, what: str) -> bool:
        return getattr(self.policy.extras, what) == "allow"

    async def on_list_resources(self, context, call_next):
        return await call_next(context) if self._extras_allowed("resources") else []

    async def on_list_resource_templates(self, context, call_next):
        return await call_next(context) if self._extras_allowed("resources") else []

    async def on_list_prompts(self, context, call_next):
        return await call_next(context) if self._extras_allowed("prompts") else []

    async def on_read_resource(self, context, call_next):
        uri = str(getattr(context.message, "uri", ""))
        principal, role = self._who()
        who, rname = principal or "unauthenticated", role.name if role else None
        if role is None or not self._extras_allowed("resources"):
            self.audit.extra(principal=who, role=rname, what="resource", name=uri, decision="deny",
                             reason="resources are denied by policy")
            raise ResourceError(f"[guard] resource '{uri}' is not permitted.")
        result = await call_next(context)
        self.audit.extra(principal=who, role=rname, what="resource", name=uri, decision="allow")
        return self._guard_resource(result)

    async def on_get_prompt(self, context, call_next):
        name = str(getattr(context.message, "name", ""))
        principal, role = self._who()
        who, rname = principal or "unauthenticated", role.name if role else None
        if role is None or not self._extras_allowed("prompts"):
            self.audit.extra(principal=who, role=rname, what="prompt", name=name, decision="deny",
                             reason="prompts are denied by policy")
            raise PromptError(f"[guard] prompt '{name}' is not permitted.")
        result = await call_next(context)
        self.audit.extra(principal=who, role=rname, what="prompt", name=name, decision="allow")
        return self._guard_prompt(result)

    def _guard_resource(self, result: Any) -> Any:
        contents = getattr(result, "contents", None)
        if isinstance(contents, str):
            return type(result)(contents=self.output.process(contents).text, meta=getattr(result, "meta", None))
        if isinstance(contents, list):
            new = []
            for c in contents:
                if isinstance(getattr(c, "content", None), str):
                    c = type(c)(content=self.output.process(c.content).text,
                                mime_type=getattr(c, "mime_type", None), meta=getattr(c, "meta", None))
                new.append(c)
            return type(result)(contents=new, meta=getattr(result, "meta", None))
        return result

    def _guard_prompt(self, result: Any) -> Any:
        messages = getattr(result, "messages", None)
        if isinstance(messages, str):
            return type(result)(messages=self.output.process(messages).text,
                                description=getattr(result, "description", None),
                                meta=getattr(result, "meta", None))
        if isinstance(messages, list):
            new = []
            for m in messages:
                content = getattr(m, "content", None)
                if isinstance(content, str):
                    m = type(m)(content=self.output.process(content).text, role=m.role)
                elif isinstance(content, mt.TextContent):
                    m = type(m)(content=mt.TextContent(type="text", text=self.output.process(content.text).text),
                                role=m.role)
                new.append(m)
            return type(result)(messages=new, description=getattr(result, "description", None),
                                meta=getattr(result, "meta", None))
        return result
