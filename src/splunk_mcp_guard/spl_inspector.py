"""SPL inspection.

Two independent views of the same query are combined, and a command has to be
acceptable in *both* for the query to pass:

1. A local tokenizer that walks the pipeline, descends into subsearches and
   ignores quoted strings.  It never talks to the network, so it works even when
   Splunk is unreachable.  It cannot expand macros.

2. Splunk's own parser (``POST /services/search/parser``), which expands macros
   and reports every command it will actually execute.  This is authoritative
   but needs credentials with search access.

Using the union of both sets means a macro that hides ``| delete`` is caught by
the parser, and a parser outage does not silently turn the guard off: the local
tokenizer still runs, and the policy decides whether a missing parser result is
fatal.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from .policy import SplPolicy

_REL_TIME = re.compile(r"^\s*(?:(-?\d+)([smhdwMyQ]|mon|min|sec|hr|day|week|month|year|quarter)s?)?(?:@[\w]+)?\s*$")
_UNIT_SECONDS = {
    "s": 1, "sec": 1, "m": 60, "min": 60, "h": 3600, "hr": 3600,
    "d": 86400, "day": 86400, "w": 604800, "week": 604800,
    "M": 2629800, "mon": 2629800, "month": 2629800,
    "Q": 7889400, "quarter": 7889400, "y": 31557600, "year": 31557600,
}
_INDEX_TERM = re.compile(r"(?<![\w.])index\s*(?:=|::|\s+IN\s*\()\s*([^\s\)\|,]+(?:\s*,\s*[^\s\)\|]+)*)", re.IGNORECASE)


@dataclass
class Inspection:
    ok: bool
    reasons: list[str] = field(default_factory=list)
    commands: set[str] = field(default_factory=set)
    indexes: set[str] = field(default_factory=set)
    parser_used: bool = False


# ------------------------------------------------------------- local tokenizer


def tokenize_commands(spl: str) -> set[str]:
    """Return the set of command names in *spl*, including subsearches.

    Rules: a pipeline stage starts after ``|`` (outside quotes) or at the very
    beginning of the query / of a ``[ ... ]`` subsearch.  The first bare word of
    a stage is its command.  A leading stage with no explicit command is the
    implicit ``search``.
    """
    cmds: set[str] = set()
    _walk(spl, cmds)
    return cmds


def _walk(text: str, out: set[str]) -> None:
    stages: list[str] = []
    buf: list[str] = []
    depth = 0
    quote: str | None = None
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if quote:
            buf.append(ch)
            if ch == "\\" and i + 1 < n:
                buf.append(text[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in ('"', "'"):
            quote = ch
            buf.append(ch)
        elif ch == "[":
            # subsearch: capture until matching ]
            j = _match_bracket(text, i)
            inner = text[i + 1 : j]
            _walk(inner, out)
            buf.append(" ")  # keep stage boundaries sane
            i = j + 1
            continue
        elif ch == "|" and depth == 0:
            stages.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
        i += 1
    stages.append("".join(buf))

    for k, stage in enumerate(stages):
        s = stage.strip()
        if not s:
            continue
        # a stage may start with a macro `name` — we cannot expand it here
        first = re.match(r"[A-Za-z_][\w\-]*", s)
        if first is None:
            if k == 0:
                out.add("search")
            continue
        word = first.group(0).lower()
        if k == 0 and not _looks_like_command(word, s):
            out.add("search")
        else:
            out.add(word)


def _looks_like_command(word: str, stage: str) -> bool:
    # first stage: `search index=x` vs `index=x` vs `tstats ...`
    rest = stage[len(word):].lstrip()
    if rest.startswith("="):
        return False  # it's a field=value term, implicit search
    return True


def _match_bracket(text: str, start: int) -> int:
    depth = 0
    quote: str | None = None
    for j in range(start, len(text)):
        ch = text[j]
        if quote:
            if ch == quote:
                quote = None
            continue
        if ch in ('"', "'"):
            quote = ch
        elif ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
            if depth == 0:
                return j
    return len(text)


def extract_indexes(spl: str) -> set[str]:
    found: set[str] = set()
    for m in _INDEX_TERM.finditer(spl):
        for raw in m.group(1).split(","):
            v = raw.strip().strip('"').strip("'")
            if v:
                found.add(v)
    return found


def relative_seconds(value: str) -> int | None:
    """``-24h`` -> 86400.  Returns None for absolute or unparseable values."""
    if value is None:
        return None
    v = str(value).strip()
    if v in {"", "now", "0"}:
        return 0
    m = _REL_TIME.match(v)
    if not m or m.group(1) is None:
        return None
    qty, unit = int(m.group(1)), m.group(2)
    return abs(qty) * _UNIT_SECONDS.get(unit, 0)


def _earliest_in_spl(spl: str) -> str | None:
    m = re.search(r"(?<![\w.])earliest\s*=\s*([^\s|]+)", spl, re.IGNORECASE)
    return m.group(1).strip('"').strip("'") if m else None


# ----------------------------------------------------------------- inspector


class SplInspector:
    def __init__(self, spl_policy: SplPolicy, parser: "SplunkParser | None" = None):
        self.policy = spl_policy
        self.parser = parser

    async def inspect(
        self,
        spl: str,
        *,
        earliest: str | None = None,
        latest: str | None = None,
        count: int | None = None,
        allowed_indexes: list[str] | None = None,
    ) -> Inspection:
        res = Inspection(ok=True)
        if not spl or not spl.strip():
            res.ok = False
            res.reasons.append("empty SPL")
            return res

        local = tokenize_commands(spl)
        res.commands |= local

        if self.policy.use_splunk_parser and self.parser is not None:
            try:
                parsed = await self.parser.commands(spl)
                res.commands |= parsed
                res.parser_used = True
            except ParserRejected as e:
                res.ok = False
                res.parser_used = True
                res.reasons.append(f"splunk parser rejected the query: {e}")
            except ParserUnavailable as e:
                res.reasons.append(f"splunk parser unavailable ({e}); local tokenizer only")

        denied = self.policy.denied()
        bad = sorted(c for c in res.commands if c in denied)
        if bad:
            res.ok = False
            res.reasons.append(f"denied command(s): {', '.join(bad)}")

        if self.policy.allowed_commands:
            allowed = set(self.policy.allowed_commands)
            unknown = sorted(c for c in res.commands if c not in allowed and c not in denied)
            if unknown:
                res.ok = False
                res.reasons.append(f"command(s) not in allowlist: {', '.join(unknown)}")

        res.indexes = extract_indexes(spl)
        if self.policy.require_index and not res.indexes and "search" in res.commands:
            res.ok = False
            res.reasons.append("search does not name an index (index=... is required)")
        if self.policy.forbid_wildcard_index and any("*" in ix for ix in res.indexes):
            res.ok = False
            res.reasons.append("wildcard index is not allowed")
        if allowed_indexes is not None:
            allowed_set = set(allowed_indexes)
            if "*" not in allowed_set:
                off = sorted(ix for ix in res.indexes if ix not in allowed_set)
                if off:
                    res.ok = False
                    res.reasons.append(f"index(es) outside principal scope: {', '.join(off)}")

        floor = relative_seconds(self.policy.earliest_floor)
        for label, val in (("earliest_time", earliest), ("earliest in SPL", _earliest_in_spl(spl))):
            if val is None:
                continue
            secs = relative_seconds(val)
            if secs is None:
                res.reasons.append(f"{label}={val!r} is absolute; not enforced by floor")
                continue
            if floor is not None and secs > floor:
                res.ok = False
                res.reasons.append(f"{label}={val} reaches past floor {self.policy.earliest_floor}")

        if count is not None and count > self.policy.max_events:
            res.ok = False
            res.reasons.append(f"count={count} exceeds max_events={self.policy.max_events}")

        return res


# ------------------------------------------------------------- splunk parser


class ParserUnavailable(RuntimeError):
    """Splunk's parser could not be reached or answered unexpectedly."""


class ParserRejected(RuntimeError):
    """Splunk's parser answered and refused the query (syntax, unknown command,
    missing privilege).  Splunk would refuse to run it too; treat as a deny."""


class SplunkParser:
    """Thin client for ``/services/search/parser``.

    Response shape (observed on Splunk 9/10, verify on yours): a JSON object with
    a ``commands`` list; each item carries the command name under ``command``.
    We also look at ``args``/``rawargs`` when present so that subsearch text is
    tokenized locally as a second opinion.
    """

    def __init__(self, base_url: str, *, token: str | None = None, username: str | None = None,
                 password: str | None = None, verify_ssl: bool = True, timeout: float = 10.0):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.timeout = timeout

    async def commands(self, spl: str) -> set[str]:
        try:
            import httpx
        except ImportError as e:  # pragma: no cover
            raise ParserUnavailable("httpx not installed") from e

        headers: dict[str, str] = {}
        auth = None
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        elif self.username and self.password:
            auth = (self.username, self.password)
        else:
            raise ParserUnavailable("no credentials configured for parser")

        q = spl.strip()
        if not q.startswith("|") and not q.lower().startswith("search "):
            q = "search " + q
        try:
            async with httpx.AsyncClient(verify=self.verify_ssl, timeout=self.timeout) as c:
                r = await c.post(
                    f"{self.base_url}/services/search/parser",
                    data={"q": q, "output_mode": "json", "parse_only": "t"},
                    headers=headers,
                    auth=auth,
                )
        except Exception as e:  # network / TLS
            raise ParserUnavailable(str(e)) from e

        if r.status_code == 400:
            # syntactically invalid SPL — Splunk would reject it anyway
            try:
                msg = "; ".join(m.get("text", "") for m in r.json().get("messages", []))
            except Exception:
                msg = r.text[:200]
            raise ParserRejected(msg)
        if r.status_code >= 300:
            raise ParserUnavailable(f"HTTP {r.status_code}")

        data: Any = r.json()
        out: set[str] = set()
        for item in data.get("commands", []) or []:
            name = item.get("command") or item.get("name")
            if name:
                out.add(str(name).lower())
            for key in ("args", "rawargs", "search"):
                v = item.get(key)
                if isinstance(v, str) and "[" in v:
                    out |= tokenize_commands(v)
        return out
