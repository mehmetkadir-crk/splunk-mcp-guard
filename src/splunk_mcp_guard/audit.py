"""Append-only audit log plus a small denial-rate alarm.

Every decision the guard makes is written as one JSON line.  Denied calls are
counted per principal inside a sliding window; crossing the threshold emits an
``alert`` record.  The intent: a restricted user (or a manipulated model acting
on their behalf) probing for tools they should not have is itself a security
event, not just a failed request.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from collections import defaultdict, deque
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .policy import AuditPolicy


@dataclass
class AuditEvent:
    ts: float
    kind: str  # decision | alert | preflight | error
    principal: str
    role: str | None
    tool: str | None
    decision: str | None  # allow | inspect-ok | inspect-deny | approve-ok | approve-deny | deny
    reason: str | None = None
    args: dict[str, Any] | None = None
    result_sha256: str | None = None
    duration_ms: float | None = None
    extra: dict[str, Any] = field(default_factory=dict)


class AuditLog:
    def __init__(self, policy: AuditPolicy):
        self.policy = policy
        self.path = Path(policy.path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._denials: dict[str, deque[float]] = defaultdict(deque)

    # ----------------------------------------------------------------- write

    def write(self, ev: AuditEvent) -> None:
        line = json.dumps(asdict(ev), ensure_ascii=False, default=str)
        with self._lock:
            with self.path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
        self._maybe_hec(ev)

    def decision(self, *, principal: str, role: str | None, tool: str, decision: str,
                 reason: str | None = None, args: dict[str, Any] | None = None,
                 result_text: str | None = None, duration_ms: float | None = None,
                 **extra: Any) -> None:
        ev = AuditEvent(
            ts=time.time(), kind="decision", principal=principal, role=role, tool=tool,
            decision=decision, reason=reason, args=self.redact(args),
            result_sha256=_sha(result_text) if result_text is not None else None,
            duration_ms=duration_ms, extra=extra,
        )
        self.write(ev)
        if decision.endswith("deny") and self.policy.alert_on_denied:
            self._count_denial(principal, tool, reason)

    def preflight(self, principal: str, ok: bool, detail: dict[str, Any]) -> None:
        self.write(AuditEvent(ts=time.time(), kind="preflight", principal=principal, role=None,
                              tool=None, decision="ok" if ok else "refused", extra=detail))

    def error(self, principal: str, tool: str | None, message: str) -> None:
        self.write(AuditEvent(ts=time.time(), kind="error", principal=principal, role=None,
                              tool=tool, decision=None, reason=message))

    # ------------------------------------------------------------- redaction

    def redact(self, args: dict[str, Any] | None) -> dict[str, Any] | None:
        if not args:
            return args
        out: dict[str, Any] = {}
        keys = set(self.policy.redact_arg_keys)
        for k, v in args.items():
            if k.lower() in keys or any(s in k.lower() for s in keys):
                out[k] = "***"
            elif isinstance(v, str) and len(v) > 4000:
                out[k] = v[:4000] + f"...(+{len(v) - 4000} chars)"
            else:
                out[k] = v
        return out

    # ------------------------------------------------------------- alarming

    def _count_denial(self, principal: str, tool: str, reason: str | None) -> None:
        now = time.time()
        dq = self._denials[principal]
        dq.append(now)
        cutoff = now - self.policy.window_seconds
        while dq and dq[0] < cutoff:
            dq.popleft()
        if len(dq) >= self.policy.denied_threshold:
            self.write(AuditEvent(
                ts=now, kind="alert", principal=principal, role=None, tool=tool,
                decision="deny-threshold",
                reason=f"{len(dq)} denied calls within {self.policy.window_seconds}s (last: {reason})",
            ))
            dq.clear()

    def _maybe_hec(self, ev: AuditEvent) -> None:
        url = self.policy.hec_url
        if not url:
            return
        token = os.environ.get(self.policy.hec_token_env)
        if not token:
            return
        try:
            import httpx
            payload = {"event": asdict(ev), "sourcetype": "mcp:guard", "source": "splunk-mcp-guard"}
            httpx.post(url.rstrip("/") + "/services/collector/event",
                       json=payload, headers={"Authorization": f"Splunk {token}"},
                       timeout=3.0, verify=False)
        except Exception:
            # never let audit shipping break the request path
            pass


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()
