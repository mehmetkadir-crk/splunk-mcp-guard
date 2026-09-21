"""Start-up check of the *backend* Splunk account.

The guard cannot see which account the wrapped MCP server uses, but it can be
told (same env vars) and then ask Splunk what that account is allowed to do.
If the account carries capabilities the policy says it should never need
(``can_delete``, ``admin_all_objects`` by default), the guard refuses to start.

This is the answer to "a fully privileged account was handed out and nobody
noticed": the guard notices, at boot, and says so.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class PreflightReport:
    ok: bool
    username: str | None = None
    roles: list[str] = field(default_factory=list)
    capabilities: set[str] = field(default_factory=set)
    offending: list[str] = field(default_factory=list)
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok, "username": self.username, "roles": self.roles,
            "offending": self.offending, "error": self.error,
            "capability_count": len(self.capabilities),
        }


async def check_backend_account(
    base_url: str, *, token: str | None, username: str | None, password: str | None,
    verify_ssl: bool, forbidden: list[str], timeout: float = 10.0,
) -> PreflightReport:
    try:
        import httpx
    except ImportError as e:  # pragma: no cover
        return PreflightReport(ok=False, error=f"httpx missing: {e}")

    headers: dict[str, str] = {}
    auth = None
    if token:
        headers["Authorization"] = f"Bearer {token}"
    elif username and password:
        auth = (username, password)
    else:
        return PreflightReport(ok=False, error="no backend credentials for preflight")

    base = base_url.rstrip("/")
    try:
        async with httpx.AsyncClient(verify=verify_ssl, timeout=timeout) as c:
            r = await c.get(f"{base}/services/authentication/current-context",
                            params={"output_mode": "json"}, headers=headers, auth=auth)
            r.raise_for_status()
            entry = (r.json().get("entry") or [{}])[0]
            content = entry.get("content", {})
            who = content.get("username") or entry.get("name")
            roles = [str(x) for x in content.get("roles", [])]
            caps: set[str] = set(str(x) for x in content.get("capabilities", []) or [])

            # capabilities on current-context are sometimes empty; walk roles
            for role in roles:
                rr = await c.get(f"{base}/services/authorization/roles/{role}",
                                 params={"output_mode": "json"}, headers=headers, auth=auth)
                if rr.status_code != 200:
                    continue
                rc = (rr.json().get("entry") or [{}])[0].get("content", {})
                caps |= set(str(x) for x in rc.get("capabilities", []) or [])
                caps |= set(str(x) for x in rc.get("imported_capabilities", []) or [])
    except Exception as e:
        return PreflightReport(ok=False, error=str(e))

    offending = sorted(c for c in caps if c in set(forbidden))
    return PreflightReport(ok=not offending, username=who, roles=roles,
                           capabilities=caps, offending=offending)
