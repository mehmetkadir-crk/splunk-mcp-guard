"""Command line entry point.

    splunk-mcp-guard --policy <policy.yaml> --backend <backend.json>
    splunk-mcp-guard init
    splunk-mcp-guard pending | approve <id> | reject <id>

The backend file is an MCP config ({"mcpServers": {...}}) that says how to
start or reach the real Splunk MCP server.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

from fastmcp.server import create_proxy

from .audit import AuditLog
from .middleware import GuardMiddleware
from .output_guard import OutputGuard
from .policy import PolicyError, load_policy
from .preflight import check_backend_account
from .spl_inspector import SplInspector, SplunkParser


def _env(name: str, default: str | None = None) -> str | None:
    v = os.environ.get(name)
    return v if v not in (None, "") else default


def build_parser_from_env() -> SplunkParser | None:
    """Parser credentials come from GUARD_SPLUNK_* first, then SPLUNK_* (shared with backend)."""
    host = _env("GUARD_SPLUNK_HOST") or _env("SPLUNK_HOST")
    if not host:
        return None
    port = _env("GUARD_SPLUNK_PORT") or _env("SPLUNK_PORT") or "8089"
    scheme = _env("GUARD_SPLUNK_SCHEME") or _env("SPLUNK_SCHEME") or "https"
    verify = (_env("GUARD_SPLUNK_VERIFY_SSL") or _env("SPLUNK_VERIFY_SSL") or "true").lower() in {"1", "true", "yes"}
    return SplunkParser(
        f"{scheme}://{host}:{port}",
        token=_env("GUARD_SPLUNK_TOKEN") or _env("SPLUNK_TOKEN"),
        username=_env("GUARD_SPLUNK_USERNAME") or _env("SPLUNK_USERNAME"),
        password=_env("GUARD_SPLUNK_PASSWORD") or _env("SPLUNK_PASSWORD"),
        verify_ssl=verify,
    )


_APPROVAL_CMDS = {"pending", "approve", "reject"}


def _approval_cli(argv: list[str]) -> int:
    """pending / approve <id> / reject <id>, run by a person in a terminal."""
    from .approval import decide, list_pending

    ap = argparse.ArgumentParser(prog=f"splunk-mcp-guard {argv[0]}")
    if argv[0] != "pending":
        ap.add_argument("id")
    ap.add_argument("--policy", help="policy YAML; its approval.dir is used")
    ap.add_argument("--dir", help="approval directory (overrides policy / GUARD_APPROVAL_DIR)")
    ap.add_argument("--by", help="name recorded as the approver")
    ns = ap.parse_args(argv[1:])

    d = ns.dir or _env("GUARD_APPROVAL_DIR")
    if not d and ns.policy:
        try:
            d = load_policy(ns.policy).approval.dir
        except (PolicyError, OSError) as e:
            print(f"[guard] policy error: {e}", file=sys.stderr)
            return 2
    if not d:
        from .init import guard_home
        home_dir = guard_home() / "approvals"
        d = str(home_dir) if home_dir.is_dir() else "./guard-approvals"

    if argv[0] == "pending":
        rows = list_pending(d)
        if not rows:
            print(f"no pending approvals in {Path(d).resolve()}")
            return 0
        for r in rows:
            flag = " (expired)" if r.get("expired") else ""
            print(f"{r['id']}{flag}  {r.get('principal')}  {r.get('tool')}  "
                  f"{json.dumps(r.get('args'), ensure_ascii=False, default=str)[:200]}")
        return 0
    print(decide(d, ns.id, argv[0], by=ns.by))
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] in _APPROVAL_CMDS:
        return _approval_cli(argv)
    if argv and argv[0] == "init":
        from .init import main as init_main
        return init_main(argv[1:])

    ap = argparse.ArgumentParser(prog="splunk-mcp-guard",
                                 description="Policy-enforcing proxy in front of any Splunk MCP server.")
    ap.add_argument("--policy", required=True, help="policy YAML (see policy/strict.yaml)")
    ap.add_argument("--backend", required=True, help="MCP config JSON describing the real Splunk MCP server")
    ap.add_argument("--transport", choices=["stdio", "http"], default="stdio")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8010)
    ap.add_argument("--skip-preflight", action="store_true", help="do not check the backend account at start")
    ap.add_argument("--print-policy", action="store_true", help="show the effective policy and exit")
    ns = ap.parse_args(argv)

    try:
        policy = load_policy(ns.policy)
    except (PolicyError, OSError) as e:
        print(f"[guard] policy error: {e}", file=sys.stderr)
        return 2

    # MCP clients start the guard from an unknown working directory
    audit_override = _env("GUARD_AUDIT_PATH")
    if audit_override:
        policy.audit.path = audit_override
    approval_override = _env("GUARD_APPROVAL_DIR")
    if approval_override:
        policy.approval.dir = approval_override

    if ns.print_policy:
        for name, role in policy.roles.items():
            print(f"role {name}: allow={sorted(role.allow)} inspect={sorted(role.inspect)} "
                  f"approve={sorted(role.approve)} deny={sorted(role.deny)} indexes={role.indexes}")
        print(f"default_role={policy.default_role} unknown_tool={policy.unknown_tool.value} "
              f"denied_commands={sorted(policy.spl.denied())}")
        return 0

    backend_cfg = json.loads(Path(ns.backend).read_text(encoding="utf-8"))
    if "mcpServers" not in backend_cfg:
        print("[guard] backend file must contain an 'mcpServers' object", file=sys.stderr)
        return 2

    if policy.identity.source == "header" and not _env(policy.identity.proxy_secret_env):
        print(f"[guard] identity.source is 'header' but {policy.identity.proxy_secret_env} is not set; "
              "refusing to start", file=sys.stderr)
        return 2
    if ns.transport == "http" and policy.identity.source != "header":
        print("[guard] WARNING: HTTP transport with identity.source "
              f"'{policy.identity.source}': every caller gets the same principal", file=sys.stderr)

    audit = AuditLog(policy.audit)
    creds = build_parser_from_env()
    parser = creds if policy.spl.use_splunk_parser else None
    inspector = SplInspector(policy.spl, parser)
    output = OutputGuard(policy.output)

    if policy.preflight.enabled and not ns.skip_preflight:
        rep = asyncio.run(_preflight(policy, creds))
        override = _env(policy.preflight.override_env, "").lower() in {"1", "true", "yes"}
        audit.preflight(principal="startup", ok=rep.ok, detail=rep.as_dict(), override=override and not rep.ok)
        if not rep.ok:
            msg = (f"[guard] preflight: account {rep.username!r} has forbidden roles/capabilities "
                   f"{rep.offending}" if rep.offending else f"[guard] preflight failed: {rep.error}")
            if not override:
                print(f"{msg}. Refusing to start. Set {policy.preflight.override_env}=1 to override.",
                      file=sys.stderr)
                return 3
            print(f"{msg}. Continuing because {policy.preflight.override_env} is set.", file=sys.stderr)

    proxy = create_proxy(backend_cfg, name="splunk-mcp-guard")
    proxy.add_middleware(GuardMiddleware(policy, audit, inspector, output))

    print(f"[guard] policy={policy.profile} ({ns.policy}) default_role={policy.default_role} "
          f"parser={'on' if parser else 'off'} transport={ns.transport} "
          f"audit={Path(policy.audit.path).resolve()} "
          f"approval={policy.approval.mode}:{Path(policy.approval.dir).resolve()}", file=sys.stderr)

    if ns.transport == "stdio":
        proxy.run(show_banner=False)
    else:
        if ns.host not in {"127.0.0.1", "localhost", "::1"}:
            print(f"[guard] WARNING: binding to {ns.host}; make sure an authenticating proxy sits in front",
                  file=sys.stderr)
        proxy.run(transport="http", host=ns.host, port=ns.port, show_banner=False)
    return 0


async def _preflight(policy, parser: SplunkParser | None):
    if parser is None:
        from .preflight import PreflightReport
        return PreflightReport(ok=False, error="no Splunk credentials available to the guard")
    return await check_backend_account(
        parser.base_url, token=parser.token, username=parser.username, password=parser.password,
        verify_ssl=parser.verify_ssl, forbidden=policy.preflight.refuse_if_backend_has,
    )


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
