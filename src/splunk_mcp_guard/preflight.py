"""Startup check of the Splunk account the guard and the MCP server use.

The guard asks Splunk who the account is and what it may do, and refuses to
start if it holds a forbidden role or capability (see policy DEFAULT_FORBIDDEN).
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
        return PreflightReport(ok=False, error="no Splunk credentials for preflight")

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
            caps: set[str] = {str(x) for x in content.get("capabilities", []) or []}

            # current-context does not always list capabilities; add the roles'
            for role in roles:
                rr = await c.get(f"{base}/services/authorization/roles/{role}",
                                 params={"output_mode": "json"}, headers=headers, auth=auth)
                if rr.status_code != 200:
                    continue
                rc = (rr.json().get("entry") or [{}])[0].get("content", {})
                caps |= {str(x) for x in rc.get("capabilities", []) or []}
                caps |= {str(x) for x in rc.get("imported_capabilities", []) or []}
                roles += [str(x) for x in rc.get("imported_roles", []) or [] if str(x) not in roles]
    except Exception as e:
        return PreflightReport(ok=False, error=f"{e.__class__.__name__}: {e}")

    if not roles and not caps:
        return PreflightReport(ok=False, username=who,
                               error="could not read the account's roles or capabilities")

    have = caps | set(roles)
    offending = sorted(x for x in set(forbidden) if x in have)
    return PreflightReport(ok=not offending, username=who, roles=roles,
                           capabilities=caps, offending=offending)
