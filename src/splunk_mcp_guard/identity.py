"""Who is asking.

stdio: the principal comes from an environment variable set in the client
config. HTTP: an authenticating reverse proxy sends the user in a header, and
proves it is the proxy with a shared secret header. Without a valid secret the
header is ignored and the call is attributed to nobody (and denied).
"""

from __future__ import annotations

import hmac
import os

from .policy import IdentityPolicy


def resolve_principal(policy: IdentityPolicy) -> str | None:
    if policy.source == "env":
        return os.environ.get(policy.env_var) or policy.default_principal
    if policy.source == "header":
        secret = os.environ.get(policy.proxy_secret_env)
        if not secret:
            return None
        try:
            from fastmcp.server.dependencies import get_http_headers
            headers = {k.lower(): v for k, v in (get_http_headers(include_all=True) or {}).items()}
        except Exception:
            return None
        sent = headers.get(policy.proxy_secret_header.lower(), "")
        if not hmac.compare_digest(str(sent).encode(), secret.encode()):
            return None
        return headers.get(policy.header.lower()) or None
    return policy.default_principal
