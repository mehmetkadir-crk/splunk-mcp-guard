"""JSONL audit log with a per-principal denial alarm and optional HEC shipping."""

from __future__ import annotations

import hashlib
import json
import os
import queue
import threading
import time
from collections import defaultdict, deque
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .output_guard import is_secret_key, redact_text
from .policy import AuditPolicy

SCHEMA = 1
MAX_VALUE = 20000


@dataclass
class AuditEvent:
    ts: float
    kind: str  # decision | alert | preflight | error | extra
    principal: str
    role: str | None
    tool: str | None
    decision: str | None
    reason: str | None = None
    args: dict[str, Any] | None = None
    result_sha256: str | None = None
    duration_ms: float | None = None
    extra: dict[str, Any] = field(default_factory=dict)
    schema: int = SCHEMA


class AuditLog:
    def __init__(self, policy: AuditPolicy):
        self.policy = policy
        self.path = Path(policy.path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.touch()
            _private(self.path)
        self._lock = threading.Lock()
        self._denials: dict[str, deque[float]] = defaultdict(deque)
        self._hec: _HecShipper | None = None
        if policy.hec_url and os.environ.get(policy.hec_token_env):
            self._hec = _HecShipper(policy, os.environ[policy.hec_token_env])

    def write(self, ev: AuditEvent) -> None:
        line = json.dumps(asdict(ev), ensure_ascii=False, default=str)
        with self._lock:
            with self.path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
        if self._hec:
            self._hec.put(ev)

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

    def preflight(self, principal: str, ok: bool, detail: dict[str, Any], override: bool = False) -> None:
        decision = "ok" if ok else ("override" if override else "refused")
        self.write(AuditEvent(ts=time.time(), kind="preflight", principal=principal, role=None,
                              tool=None, decision=decision, extra=detail))
        if override:
            self.write(AuditEvent(ts=time.time(), kind="alert", principal=principal, role=None,
                                  tool=None, decision="preflight-override",
                                  reason=f"started despite failed preflight: {detail}"))

    def error(self, principal: str, tool: str | None, message: str) -> None:
        self.write(AuditEvent(ts=time.time(), kind="error", principal=principal, role=None,
                              tool=tool, decision=None, reason=message))

    def extra(self, *, principal: str, role: str | None, what: str, name: str, decision: str,
              reason: str | None = None) -> None:
        self.write(AuditEvent(ts=time.time(), kind="extra", principal=principal, role=role,
                              tool=f"{what}:{name}", decision=decision, reason=reason))
        if decision.endswith("deny") and self.policy.alert_on_denied:
            self._count_denial(principal, f"{what}:{name}", reason)

    def redact(self, args: Any, key: str | None = None) -> Any:
        keys = set(self.policy.redact_arg_keys)
        if isinstance(args, dict):
            return {k: self.redact(v, str(k)) for k, v in args.items()}
        if isinstance(args, list):
            return [self.redact(v, key) for v in args]
        if key is not None and (key.lower() in keys or is_secret_key(key)):
            return "***"
        if isinstance(args, str):
            v, _ = redact_text(args)
            if len(v) > MAX_VALUE:
                return f"{v[:MAX_VALUE]}...(+{len(v) - MAX_VALUE} chars, sha256={_sha(args)})"
            return v
        return args

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


class _HecShipper:
    """Sends events to Splunk HEC from a background thread.

    Events that cannot be delivered are dropped; the local file stays the
    source of truth.
    """

    def __init__(self, policy: AuditPolicy, token: str):
        self.url = str(policy.hec_url).rstrip("/") + "/services/collector/event"
        self.token = token
        self.index = policy.hec_index
        self.verify: bool | str = policy.hec_ca_bundle or policy.hec_verify_tls
        self.q: queue.Queue[AuditEvent] = queue.Queue(maxsize=10000)
        threading.Thread(target=self._run, name="guard-hec", daemon=True).start()

    def put(self, ev: AuditEvent) -> None:
        try:
            self.q.put_nowait(ev)
        except queue.Full:
            pass

    def _run(self) -> None:
        import httpx
        with httpx.Client(verify=self.verify, timeout=5.0) as client:
            while True:
                ev = self.q.get()
                payload: dict[str, Any] = {"time": ev.ts, "event": asdict(ev),
                                           "sourcetype": "mcp:guard", "source": "splunk-mcp-guard"}
                if self.index:
                    payload["index"] = self.index
                for attempt in range(3):
                    try:
                        r = client.post(self.url, json=payload,
                                        headers={"Authorization": f"Splunk {self.token}"})
                        if r.status_code < 500:
                            break
                    except Exception:
                        pass
                    time.sleep(2 ** attempt)


def _private(path: Path) -> None:
    if os.name != "nt":
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()
