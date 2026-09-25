"""Policy file model: roles, tool classes, SPL rules and the other settings."""

from __future__ import annotations

import enum
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


class ToolClass(str, enum.Enum):
    ALLOW = "allow"
    INSPECT = "inspect"
    APPROVE = "approve"
    DENY = "deny"


# Never allowed, whatever the policy says: they delete or write data, send it
# out of Splunk, run code, or run SPL the guard cannot see.
HARD_DENY_COMMANDS: frozenset[str] = frozenset(
    {
        "delete",
        "outputlookup",
        "outputcsv",
        "outputtext",
        "collect",
        "mcollect",
        "meventcollect",
        "tscollect",
        "summaryindex",
        "sendemail",
        "sendalert",
        "script",
        "runshellscript",
        "run",
        "map",
        "savedsearch",
        "dump",
        "outputtelemetry",
        "sendresults",
        "dbxquery",
        "dbxoutput",
        "ldapmodify",
        "deletemodel",
        "sistats",
        "sitop",
        "sirare",
        "sichart",
        "sitimechart",
    }
)


@dataclass
class SplPolicy:
    use_splunk_parser: bool = True
    require_parser: bool = True
    allowed_commands: list[str] = field(default_factory=list)  # empty = denylist only
    denied_commands: list[str] = field(default_factory=list)
    max_events: int = 1000
    earliest_floor: str = "-30d"
    forbid_wildcard_index: bool = True
    require_index: bool = True

    def denied(self) -> frozenset[str]:
        return HARD_DENY_COMMANDS | frozenset(c.lower() for c in self.denied_commands)


@dataclass
class RolePolicy:
    name: str
    allow: set[str] = field(default_factory=set)
    inspect: set[str] = field(default_factory=set)
    approve: set[str] = field(default_factory=set)
    deny: set[str] = field(default_factory=set)
    indexes: list[str] | None = None  # None or ["*"] = no index scope
    spl_args: dict[str, list[str]] = field(default_factory=dict)


@dataclass
class IdentityPolicy:
    source: str = "env"  # env | header | none
    env_var: str = "GUARD_PRINCIPAL"
    header: str = "X-Guard-Principal"
    default_principal: str = "anonymous"
    proxy_secret_env: str = "GUARD_PROXY_SECRET"
    proxy_secret_header: str = "X-Guard-Proxy-Secret"


@dataclass
class PreflightPolicy:
    enabled: bool = True
    refuse_if_backend_has: list[str] = field(
        default_factory=lambda: list(DEFAULT_FORBIDDEN)
    )
    override_env: str = "GUARD_ALLOW_OVERPRIVILEGED"


@dataclass
class AuditPolicy:
    path: str = "./guard-audit.jsonl"
    alert_on_denied: bool = True
    denied_threshold: int = 3
    window_seconds: int = 300
    hec_url: str | None = None
    hec_token_env: str = "GUARD_HEC_TOKEN"
    hec_verify_tls: bool = True
    hec_ca_bundle: str | None = None
    hec_index: str | None = None
    redact_arg_keys: list[str] = field(
        default_factory=lambda: ["password", "token", "secret", "authorization"]
    )


@dataclass
class ApprovalPolicy:
    mode: str = "auto"  # elicit | file | auto
    dir: str = "./guard-approvals"
    timeout_seconds: int = 120
    poll_seconds: float = 1.0


@dataclass
class OutputPolicy:
    tag_untrusted: bool = True
    detect_injection: bool = True
    redact_secrets: bool = True


@dataclass
class ExtrasPolicy:
    resources: str = "deny"  # deny | allow
    prompts: str = "deny"


@dataclass
class Policy:
    version: int
    profile: str
    default_role: str
    unknown_tool: ToolClass
    spl: SplPolicy
    roles: dict[str, RolePolicy]
    principals: dict[str, str]
    identity: IdentityPolicy
    preflight: PreflightPolicy
    approval: ApprovalPolicy
    audit: AuditPolicy
    output: OutputPolicy
    extras: ExtrasPolicy = field(default_factory=ExtrasPolicy)
    source_path: str | None = None

    def role_for(self, principal: str) -> RolePolicy:
        name = self.principals.get(principal.casefold(), self.default_role)
        if name not in self.roles:
            raise PolicyError(f"principal {principal!r} maps to unknown role {name!r}")
        return self.roles[name]

    def classify(self, role: RolePolicy, tool: str) -> ToolClass:
        # a tool listed twice gets the stricter class
        if tool in role.deny:
            return ToolClass.DENY
        if tool in role.approve:
            return ToolClass.APPROVE
        if tool in role.inspect:
            return ToolClass.INSPECT
        if tool in role.allow:
            return ToolClass.ALLOW
        return self.unknown_tool

    def spl_args_for(self, role: RolePolicy, tool: str) -> list[str]:
        if tool in role.spl_args:
            return role.spl_args[tool]
        return ["query", "spl", "search", "search_query"]


class PolicyError(ValueError):
    pass


DEFAULT_FORBIDDEN = (
    "can_delete",          # role
    "delete_by_keyword",   # the capability behind | delete
    "admin_all_objects",
    "edit_user",
    "edit_roles",
    "edit_roles_grantable",
    "change_authentication",
)


def _as_set(v: Any) -> set[str]:
    if v is None:
        return set()
    if isinstance(v, str):
        return {v}
    return {str(x) for x in v}


def load_policy(path: str | os.PathLike[str]) -> Policy:
    p = Path(path)
    raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    try:
        return _build(raw, str(p))
    except KeyError as e:  # pragma: no cover
        raise PolicyError(f"policy {p}: missing key {e}") from e


def _build(raw: dict[str, Any], source: str | None) -> Policy:
    version = int(raw.get("version", 1))
    if version != 1:
        raise PolicyError(f"unsupported policy version {version}")

    defaults = raw.get("defaults", {}) or {}
    unknown = ToolClass(str(defaults.get("unknown_tool", "deny")).lower())
    default_role = str(defaults.get("role", "analyst"))

    spl_raw = raw.get("spl", {}) or {}
    spl = SplPolicy(
        use_splunk_parser=bool(spl_raw.get("use_splunk_parser", True)),
        require_parser=bool(spl_raw.get("require_parser", True)),
        allowed_commands=[str(c).lower() for c in spl_raw.get("allowed_commands", []) or []],
        denied_commands=[str(c).lower() for c in spl_raw.get("denied_commands", []) or []],
        max_events=int(spl_raw.get("max_events", 1000)),
        earliest_floor=str(spl_raw.get("earliest_floor", "-30d")),
        forbid_wildcard_index=bool(spl_raw.get("forbid_wildcard_index", True)),
        require_index=bool(spl_raw.get("require_index", True)),
    )

    roles: dict[str, RolePolicy] = {}
    for name, r in (raw.get("roles", {}) or {}).items():
        r = r or {}
        tools = r.get("tools", {}) or {}
        idx = r.get("indexes")
        roles[str(name)] = RolePolicy(
            name=str(name),
            allow=_as_set(tools.get("allow")),
            inspect=_as_set(tools.get("inspect")),
            approve=_as_set(tools.get("approve")),
            deny=_as_set(tools.get("deny")),
            indexes=None if idx is None else [str(i) for i in idx],
            spl_args={str(k): [str(a) for a in v] for k, v in (r.get("spl_args", {}) or {}).items()},
        )
    if not roles:
        raise PolicyError("policy defines no roles")
    if default_role not in roles:
        raise PolicyError(f"default role {default_role!r} is not defined")

    principals = {str(k).casefold(): str(v) for k, v in (raw.get("principals", {}) or {}).items()}
    for who, role in principals.items():
        if role not in roles:
            raise PolicyError(f"principal {who!r} maps to unknown role {role!r}")

    id_raw = raw.get("identity", {}) or {}
    identity = IdentityPolicy(
        source=str(id_raw.get("source", "env")),
        env_var=str(id_raw.get("env_var", "GUARD_PRINCIPAL")),
        header=str(id_raw.get("header", "X-Guard-Principal")),
        default_principal=str(id_raw.get("default_principal", "anonymous")),
        proxy_secret_env=str(id_raw.get("proxy_secret_env", "GUARD_PROXY_SECRET")),
        proxy_secret_header=str(id_raw.get("proxy_secret_header", "X-Guard-Proxy-Secret")),
    )
    if identity.source not in {"env", "header", "none"}:
        raise PolicyError(f"identity.source must be env|header|none, got {identity.source!r}")

    pf_raw = raw.get("preflight", {}) or {}
    preflight = PreflightPolicy(
        enabled=bool(pf_raw.get("enabled", True)),
        refuse_if_backend_has=[str(c) for c in pf_raw.get("refuse_if_backend_has", DEFAULT_FORBIDDEN)],
        override_env=str(pf_raw.get("override_env", "GUARD_ALLOW_OVERPRIVILEGED")),
    )

    au_raw = raw.get("audit", {}) or {}
    audit = AuditPolicy(
        path=str(au_raw.get("path", "./guard-audit.jsonl")),
        alert_on_denied=bool(au_raw.get("alert_on_denied", True)),
        denied_threshold=int(au_raw.get("denied_threshold", 3)),
        window_seconds=int(au_raw.get("window_seconds", 300)),
        hec_url=au_raw.get("hec_url"),
        hec_token_env=str(au_raw.get("hec_token_env", "GUARD_HEC_TOKEN")),
        hec_verify_tls=bool(au_raw.get("hec_verify_tls", True)),
        hec_ca_bundle=au_raw.get("hec_ca_bundle"),
        hec_index=au_raw.get("hec_index"),
        redact_arg_keys=[str(k).lower() for k in au_raw.get("redact_arg_keys", ["password", "token", "secret", "authorization"])],
    )

    ap_raw = raw.get("approval", {}) or {}
    approval = ApprovalPolicy(
        mode=str(ap_raw.get("mode", "auto")).lower(),
        dir=str(ap_raw.get("dir", "./guard-approvals")),
        timeout_seconds=int(ap_raw.get("timeout_seconds", 120)),
        poll_seconds=float(ap_raw.get("poll_seconds", 1.0)),
    )
    if approval.mode not in {"elicit", "file", "auto"}:
        raise PolicyError(f"approval.mode must be elicit|file|auto, got {approval.mode!r}")

    out_raw = raw.get("output", {}) or {}
    output = OutputPolicy(
        tag_untrusted=bool(out_raw.get("tag_untrusted", True)),
        detect_injection=bool(out_raw.get("detect_injection", True)),
        redact_secrets=bool(out_raw.get("redact_secrets", True)),
    )

    ex_raw = raw.get("extras", {}) or {}
    extras = ExtrasPolicy(
        resources=str(ex_raw.get("resources", "deny")).lower(),
        prompts=str(ex_raw.get("prompts", "deny")).lower(),
    )
    for k, v in (("resources", extras.resources), ("prompts", extras.prompts)):
        if v not in {"deny", "allow"}:
            raise PolicyError(f"extras.{k} must be deny|allow, got {v!r}")

    return Policy(
        version=version,
        profile=str(raw.get("profile", "custom")),
        default_role=default_role,
        unknown_tool=unknown,
        spl=spl,
        roles=roles,
        principals=principals,
        identity=identity,
        preflight=preflight,
        approval=approval,
        audit=audit,
        output=output,
        extras=extras,
        source_path=source,
    )
