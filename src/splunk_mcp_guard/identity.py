"""Who is asking?

The MCP client rarely tells us.  In stdio mode the guard runs as a child of a
desktop app on one person's machine, so the principal is configured once
(``GUARD_PRINCIPAL=ahmet``).  In HTTP mode a front proxy or the client itself
can send a header (``X-Guard-Principal``) after authenticating the user.

If the policy says ``source: none`` every call is attributed to the default
principal and the default role applies.  That is a conscious, visible choice,
not a silent fallback.
"""

from __future__ import annotations

import os

from .policy import IdentityPolicy


def resolve_principal(policy: IdentityPolicy) -> str:
    if policy.source == "env":
        return os.environ.get(policy.env_var) or policy.default_principal
    if policy.source == "header":
        try:
            from fastmcp.server.dependencies import get_http_headers
            headers = get_http_headers() or {}
        except Exception:
            headers = {}
        # header names arrive lower-cased in most ASGI stacks
        for k, v in headers.items():
            if k.lower() == policy.header.lower() and v:
                return str(v)
        return policy.default_principal
    return policy.default_principal
