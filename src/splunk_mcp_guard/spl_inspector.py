"""SPL inspection.

A query passes only if both the local tokenizer and Splunk's own parser
(/services/search/parser) accept it. The tokenizer works offline and walks
subsearches; the parser expands macros. When the parser is required but not
reachable, the query is rejected.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .policy import HARD_DENY_COMMANDS, SplPolicy

# Commands that may appear at the very start of a query without a leading pipe.
# Anything else there is a search term ("error | head 10" searches for "error").
# Hard-denied commands are included so a backend that forwards "delete ..."
# verbatim is still caught.
_FIRST_STAGE_COMMANDS = HARD_DENY_COMMANDS | frozenset({
    "search", "tstats", "mstats", "mcatalog", "inputlookup", "inputcsv", "makeresults",
    "metadata", "metasearch", "datamodel", "from", "pivot", "dbinspect", "eventcount",
    "multisearch", "loadjob", "savedsearch", "gentimes", "rest", "set", "append",
    "union", "walklex", "typeahead", "history", "audit",
})

# First commands of a pipeline that read no index.
_NO_INDEX_COMMANDS = frozenset({
    "makeresults", "inputlookup", "inputcsv", "rest", "gentimes",
    "multisearch", "union", "set", "append",
})
# First commands that take index= arguments we can check.
_INDEX_ARG_COMMANDS = frozenset({"metadata", "eventcount", "dbinspect"})
_WHERE_COMMANDS = frozenset({"tstats", "mstats"})

_IDX_VAL = r'(?:"[^"]*"|[^\s()|"\[\],]+)'
_IDX_TERM = rf"index\s*(?:=|::)\s*{_IDX_VAL}"
_IDX_IN = r"index\s+IN\s*\([^)]*\)"
_IDX_ANY = rf"(?:{_IDX_TERM}|{_IDX_IN})"
_IDX_GROUP = re.compile(rf"\s*(?:{_IDX_ANY}|\(\s*{_IDX_ANY}(?:\s+OR\s+{_IDX_ANY})*\s*\))", re.I)
_INDEX_TERM = re.compile(r"(?<![\w.])index\s*(?:=|::)\s*(\"[^\"]*\"|[^\s()|\"\[\],]+)", re.I)
_INDEX_IN = re.compile(r"(?<![\w.])index\s+IN\s*\(([^)]*)\)", re.I)
_EARLIEST = re.compile(r"(?<![\w.])(earliest|starttime|starttimeu)\s*=\s*(\"[^\"]*\"|[^\s|\[\]()]+)", re.I)
_COMMENT = re.compile(r"```.*?```", re.S)
_WORD = re.compile(r"[A-Za-z_][\w-]*")

_UNITS: dict[str, int] = {}
for _names, _secs in (
    (("s", "sec", "secs", "second", "seconds"), 1),
    (("m", "min", "mins", "minute", "minutes"), 60),
    (("h", "hr", "hrs", "hour", "hours"), 3600),
    (("d", "day", "days"), 86400),
    (("w", "week", "weeks"), 604800),
    (("mon", "month", "months"), 2629800),
    (("q", "qtr", "qtrs", "quarter", "quarters"), 7889400),
    (("y", "yr", "yrs", "year", "years"), 31557600),
):
    for _n in _names:
        _UNITS[_n] = _secs

_RELATIVE = re.compile(r"([+-])?(\d*)([a-z]+)?(?:@([a-z]+?)\d*(?:[+-]\d*[a-z]+)?)?")
_ABS_FORMATS = ("%m/%d/%Y:%H:%M:%S", "%m/%d/%Y", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d")


@dataclass
class Stage:
    text: str
    command: str | None
    body: str = ""
    macro: bool = False


@dataclass
class Pipeline:
    stages: list[Stage]
    leading_pipe: bool = False


@dataclass
class Scan:
    pipelines: list[Pipeline] = field(default_factory=list)
    commands: set[str] = field(default_factory=set)
    has_macro: bool = False
    problems: list[str] = field(default_factory=list)
    text: str = ""


@dataclass
class Inspection:
    ok: bool
    reasons: list[str] = field(default_factory=list)
    commands: set[str] = field(default_factory=set)
    indexes: set[str] = field(default_factory=set)
    parser_used: bool = False


def scan(spl: str) -> Scan:
    out = Scan()
    if spl.count("```") % 2:
        out.problems.append("unbalanced ``` comment")
    text = _COMMENT.sub(" ", spl)
    out.text = text
    out.has_macro = "`" in text
    _parse(text, out)
    for p in out.pipelines:
        for st in p.stages:
            if st.command:
                out.commands.add(st.command)
    return out


def tokenize_commands(spl: str) -> set[str]:
    return scan(spl).commands


def _parse(text: str, out: Scan) -> None:
    stages: list[str] = []
    buf: list[str] = []
    in_quote = False
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if in_quote:
            buf.append(ch)
            if ch == "\\" and i + 1 < n:
                buf.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_quote = False
        elif ch == '"':
            in_quote = True
            buf.append(ch)
        elif ch == "[":
            j = _match_bracket(text, i)
            if j < 0:
                out.problems.append("unbalanced [ ]")
                buf.append(text[i + 1:])
                break
            _parse(text[i + 1:j], out)
            buf.append(" [] ")
            i = j + 1
            continue
        elif ch == "]":
            out.problems.append("unbalanced [ ]")
        elif ch == "|":
            stages.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
        i += 1
    if in_quote:
        out.problems.append("unbalanced quotes")
    stages.append("".join(buf))

    leading_pipe = False
    if len(stages) > 1 and not stages[0].strip():
        leading_pipe = True
        stages = stages[1:]
    pipe = Pipeline(stages=[], leading_pipe=leading_pipe)
    for k, raw in enumerate(stages):
        s = raw.strip()
        if not s:
            if len(stages) > 1:
                out.problems.append("empty pipeline stage")
            continue
        pipe.stages.append(_stage(s, first=(k == 0 and not leading_pipe), out=out))
    out.pipelines.append(pipe)


def _stage(s: str, first: bool, out: Scan) -> Stage:
    if s.startswith("`"):
        return Stage(text=s, command=None, macro=True)
    m = _WORD.match(s)
    if m is None:
        if first:
            return Stage(text=s, command="search", body=s)
        out.problems.append(f"cannot identify the command in stage {s[:40]!r}")
        return Stage(text=s, command=None)
    word = m.group(0).lower()
    rest = s[m.end():]
    if first and (rest.lstrip().startswith("=") or word not in _FIRST_STAGE_COMMANDS):
        return Stage(text=s, command="search", body=s)
    return Stage(text=s, command=word, body=rest.strip())


def _match_bracket(text: str, start: int) -> int:
    depth = 0
    in_quote = False
    j = start
    while j < len(text):
        ch = text[j]
        if in_quote:
            if ch == "\\":
                j += 2
                continue
            if ch == '"':
                in_quote = False
        elif ch == '"':
            in_quote = True
        elif ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
            if depth == 0:
                return j
        j += 1
    return -1


def extract_indexes(spl: str) -> set[str]:
    found: set[str] = set()
    for m in _INDEX_TERM.finditer(spl):
        v = m.group(1).strip().strip('"')
        if v:
            found.add(v)
    for m in _INDEX_IN.finditer(spl):
        for raw in m.group(1).split(","):
            v = raw.strip().strip('"').strip("'")
            if v:
                found.add(v)
    return found


def starts_with_index_group(body: str) -> bool:
    """True if the clause starts with index terms that are ANDed with the rest.

    OR binds tighter than the implicit AND in SPL: "index=a foo OR bar" is
    index=a AND (foo OR bar), but "index=a OR foo" is not limited to index a.
    """
    m = _IDX_GROUP.match(body)
    if not m:
        return False
    rest = body[m.end():]
    if not rest.strip():
        return True
    if not rest[0].isspace():
        return False
    if re.match(r"or(?![\w=])", rest.lstrip(), re.I):
        return False
    return rest.count("(") == rest.count(")")


def seconds_back(value: str, now: float | None = None) -> float | None:
    """How far into the past a time modifier reaches, in seconds. None if unknown."""
    now = time.time() if now is None else now
    raw = str(value).strip().strip('"').strip("'")
    v = raw.lower()
    if v.startswith("rt"):
        v = v[2:]
    if v in {"", "now"}:
        return 0.0
    if re.fullmatch(r"\d+(\.\d+)?", v):
        return max(0.0, now - float(v))  # plain number = epoch; 0 means all time
    m = _RELATIVE.fullmatch(v)
    if m and (m.group(3) or m.group(4)):
        sign, qty, unit, snap = m.groups()
        if (unit and unit not in _UNITS) or (snap and snap not in _UNITS) or (unit and not sign):
            return None
        back = 0.0
        if unit and sign == "-":
            back = (int(qty) if qty else 1) * _UNITS[unit]
        # snapping to a day or less is noise; to a week/month/year it reaches further back
        if snap and (_UNITS[snap] > 86400 or not unit):
            back += _UNITS[snap]
        return back
    for fmt in _ABS_FORMATS:
        try:
            ts = datetime.strptime(raw.rstrip("Z"), fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        return max(0.0, now - ts.timestamp())
    return None


def relative_seconds(value: str) -> float | None:
    return seconds_back(value)


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
        count: Any = None,
        allowed_indexes: list[str] | None = None,
    ) -> Inspection:
        res = Inspection(ok=True)

        def deny(msg: str) -> None:
            res.ok = False
            res.reasons.append(msg)

        if not spl or not spl.strip():
            deny("empty SPL")
            return res

        sc = scan(spl)
        res.commands |= sc.commands
        for p in sc.problems:
            deny(p)

        pol = self.policy
        if pol.use_splunk_parser:
            if self.parser is None:
                if pol.require_parser:
                    deny("splunk parser required but not configured")
            else:
                try:
                    res.commands |= await self.parser.commands(spl)
                    res.parser_used = True
                except ParserRejected as e:
                    res.parser_used = True
                    deny(f"splunk parser rejected the query: {e}")
                except ParserUnavailable as e:
                    if pol.require_parser:
                        deny(f"splunk parser required but unavailable ({e})")
                    else:
                        res.reasons.append(f"splunk parser unavailable ({e}); local checks only")

        scoped = allowed_indexes is not None and "*" not in allowed_indexes
        if sc.has_macro:
            if scoped:
                deny("macros are not allowed for roles with an index scope")
            elif not res.parser_used:
                deny("macros need the splunk parser")

        denied = pol.denied()
        bad = sorted(c for c in res.commands if c in denied)
        if bad:
            deny(f"denied command(s): {', '.join(bad)}")
        if pol.allowed_commands:
            allowed = set(pol.allowed_commands)
            unknown = sorted(c for c in res.commands if c not in allowed and c not in denied)
            if unknown:
                deny(f"command(s) not in allowlist: {', '.join(unknown)}")

        res.indexes = extract_indexes(sc.text)
        if pol.forbid_wildcard_index and any("*" in ix for ix in res.indexes):
            deny("wildcard index is not allowed")
        if scoped:
            off = sorted(ix for ix in res.indexes if ix not in set(allowed_indexes or []))
            if off:
                deny(f"index(es) outside principal scope: {', '.join(off)}")
        for msg in self._scope_problems(sc, scoped):
            deny(msg)

        floor = seconds_back(pol.earliest_floor) if pol.earliest_floor else None
        if floor is not None:
            values = [(f"{m.group(1)} in SPL", m.group(2)) for m in _EARLIEST.finditer(sc.text)]
            if earliest is not None:
                values.append(("earliest_time", str(earliest)))
            for label, val in values:
                back = seconds_back(val)
                if back is None:
                    deny(f"{label}={val!r} cannot be evaluated")
                elif back > floor + 60:
                    deny(f"{label}={val} reaches past floor {pol.earliest_floor}")

        if count is not None:
            for c in count if isinstance(count, (list, tuple)) else [count]:
                n = _as_int(c)
                if n is None:
                    deny(f"count={c!r} is not a number")
                elif n <= 0:
                    deny(f"count={n} is unbounded; use a positive value")
                elif n > pol.max_events:
                    deny(f"count={n} exceeds max_events={pol.max_events}")

        return res

    def _scope_problems(self, sc: Scan, scoped: bool) -> list[str]:
        out: list[str] = []
        for p in sc.pipelines:
            if not p.stages:
                continue
            first = p.stages[0]
            cmd = first.command
            if first.macro or cmd is None:
                continue
            if cmd in ("search", "metasearch"):
                if scoped and not starts_with_index_group(first.body):
                    out.append("each search must start with index=... (or index terms joined "
                               "by OR in parentheses) and must not be followed by OR")
                elif not scoped and self.policy.require_index and not extract_indexes(first.body):
                    out.append("search does not name an index (index=... is required)")
            elif cmd in _WHERE_COMMANDS:
                parts = re.split(r"\bwhere\b", first.body, maxsplit=1, flags=re.I)
                clause = parts[1] if len(parts) == 2 else ""
                if scoped and not starts_with_index_group(clause):
                    out.append(f"{cmd} needs 'where index=...' for this role")
                elif not scoped and self.policy.require_index and not extract_indexes(clause):
                    out.append(f"{cmd} does not name an index (where index=... is required)")
            elif cmd in _INDEX_ARG_COMMANDS:
                if scoped and (not extract_indexes(first.body) or re.search(r"!=|\bOR\b|\bNOT\b", first.body)):
                    out.append(f"{cmd} must name only in-scope indexes for this role")
            elif cmd in _NO_INDEX_COMMANDS:
                continue
            elif scoped:
                out.append(f"cannot check the index scope of '{cmd}'; not allowed for this role")
        return out


def _as_int(v: Any) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


class ParserUnavailable(RuntimeError):
    """The parser could not be reached or answered unexpectedly."""


class ParserRejected(RuntimeError):
    """The parser answered and refused the query; Splunk would refuse it too."""


class SplunkParser:
    """Client for /services/search/parser with parse_only=t."""

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
        except Exception as e:
            raise ParserUnavailable(str(e)) from e

        if r.status_code == 400:
            try:
                msg = "; ".join(m.get("text", "") for m in r.json().get("messages", []))
            except Exception:
                msg = r.text[:200]
            raise ParserRejected(msg)
        if r.status_code >= 300:
            raise ParserUnavailable(f"HTTP {r.status_code}")
        try:
            items = r.json().get("commands", []) or []
        except Exception as e:
            raise ParserUnavailable(f"unexpected parser response: {e}") from e

        out: set[str] = set()
        for item in items:
            if not isinstance(item, dict):
                continue
            name = item.get("command") or item.get("name")
            if name:
                out.add(str(name).lower())
            for key in ("args", "rawargs", "search"):
                v = item.get(key)
                if isinstance(v, str) and "[" in v:
                    out |= tokenize_commands(v)
        return out
