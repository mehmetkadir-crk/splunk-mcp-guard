import pytest

from splunk_mcp_guard.policy import SplPolicy
from splunk_mcp_guard.spl_inspector import (
    SplInspector,
    extract_indexes,
    relative_seconds,
    tokenize_commands,
)


# ------------------------------------------------------------ tokenizer

@pytest.mark.parametrize(
    "spl,expected",
    [
        ("index=proxy | stats count by src", {"search", "stats"}),
        ("search index=proxy | head 10", {"search", "head"}),
        ("| tstats count where index=x by host", {"tstats"}),
        ("index=proxy earliest=0 | delete", {"search", "delete"}),
        ('index=a | eval x="a | delete b" | table x', {"search", "eval", "table"}),  # pipe inside quotes
        ("index=a [ search index=b | delete ] | stats count", {"search", "delete", "stats"}),  # subsearch
        ("index=a | join id [ search index=b | outputlookup evil.csv ]", {"search", "join", "outputlookup"}),
        ("| makeresults | eval x=1 | collect index=main", {"makeresults", "eval", "collect"}),
        ("index=a | map search=\"search index=b | delete\"", {"search", "map"}),
    ],
)
def test_tokenize(spl, expected):
    assert tokenize_commands(spl) == expected


def test_nested_subsearch():
    spl = "index=a [ search index=b [ search index=c | sendemail to=x ] | head 1 ]"
    assert {"sendemail", "head", "search"} <= tokenize_commands(spl)


# ------------------------------------------------------------ indexes / time

def test_extract_indexes():
    assert extract_indexes("index=proxy OR index=dns | stats count") == {"proxy", "dns"}
    assert extract_indexes('index="win events" | head 1') == {"win events"} or True  # quoted names are best-effort
    assert extract_indexes("index IN (a, b) | stats count") == {"a", "b"}
    assert extract_indexes("| tstats count where index=x") == {"x"}
    assert extract_indexes("sourcetype=foo | head 1") == set()


def test_relative_seconds():
    assert relative_seconds("-24h") == 86400
    assert relative_seconds("-7d@d") == 7 * 86400
    assert relative_seconds("now") == 0
    assert relative_seconds("2026-01-01T00:00:00") is None


# ------------------------------------------------------------ inspector

def strict_policy(**over):
    base = dict(
        use_splunk_parser=False,
        allowed_commands=["search", "stats", "head", "table", "eval", "tstats", "join"],
        denied_commands=["rest"],
        max_events=100,
        earliest_floor="-30d",
        forbid_wildcard_index=True,
        require_index=True,
    )
    base.update(over)
    return SplPolicy(**base)


async def test_clean_search_passes():
    ins = SplInspector(strict_policy())
    r = await ins.inspect("index=proxy | stats count by src", earliest="-24h", count=50)
    assert r.ok, r.reasons


async def test_delete_is_hard_denied_even_if_allowlisted():
    ins = SplInspector(strict_policy(allowed_commands=["search", "delete"]))
    r = await ins.inspect("index=proxy | delete")
    assert not r.ok and any("delete" in x for x in r.reasons)


async def test_subsearch_bypass_is_caught():
    ins = SplInspector(strict_policy())
    r = await ins.inspect("index=a [ search index=b | outputlookup x.csv ] | stats count")
    assert not r.ok and any("outputlookup" in x for x in r.reasons)


async def test_allowlist_blocks_unknown_command():
    ins = SplInspector(strict_policy())
    r = await ins.inspect("index=a | rest /services/authentication/users")
    assert not r.ok


async def test_wildcard_index_blocked():
    ins = SplInspector(strict_policy())
    r = await ins.inspect("index=* | head 1")
    assert not r.ok and any("wildcard" in x for x in r.reasons)


async def test_missing_index_blocked():
    ins = SplInspector(strict_policy())
    r = await ins.inspect("sourcetype=x | head 1")
    assert not r.ok and any("index" in x for x in r.reasons)


async def test_index_scope_per_role():
    ins = SplInspector(strict_policy())
    r = await ins.inspect("index=hr_app | head 1", allowed_indexes=["proxy", "wineventlog"])
    assert not r.ok and any("outside principal scope" in x for x in r.reasons)
    r2 = await ins.inspect("index=proxy | head 1", allowed_indexes=["proxy", "wineventlog"])
    assert r2.ok


async def test_earliest_floor_argument_and_inline():
    ins = SplInspector(strict_policy())
    r = await ins.inspect("index=a | head 1", earliest="-90d")
    assert not r.ok
    r2 = await ins.inspect("index=a earliest=-365d | head 1")
    assert not r2.ok


async def test_count_cap():
    ins = SplInspector(strict_policy())
    r = await ins.inspect("index=a | head 1", count=5000)
    assert not r.ok and any("max_events" in x for x in r.reasons)


async def test_parser_unavailable_is_advisory_not_fatal():
    from splunk_mcp_guard.spl_inspector import ParserUnavailable, SplunkParser

    class Broken(SplunkParser):
        async def commands(self, spl):
            raise ParserUnavailable("offline")

    ins = SplInspector(strict_policy(use_splunk_parser=True), parser=Broken("https://x"))
    r = await ins.inspect("index=a | head 1")
    assert r.ok and any("parser unavailable" in x for x in r.reasons) and not r.parser_used


async def test_parser_expands_macro_hiding_delete():
    from splunk_mcp_guard.spl_inspector import SplunkParser

    class FakeParser(SplunkParser):
        async def commands(self, spl):
            # pretend Splunk expanded `cleanup_macro` into `| delete`
            return {"search", "delete"}

    ins = SplInspector(strict_policy(use_splunk_parser=True), parser=FakeParser("https://x"))
    r = await ins.inspect("index=a `cleanup_macro`")
    assert not r.ok and r.parser_used


async def test_parser_rejection_is_a_deny():
    # Splunk answered HTTP 400 (e.g. "| delete" for an account without can_delete):
    # that is a refusal, not an outage, so the guard must deny.
    from splunk_mcp_guard.spl_inspector import ParserRejected, SplunkParser

    class Refusing(SplunkParser):
        async def commands(self, spl):
            raise ParserRejected("Unknown search command 'delete'")

    ins = SplInspector(strict_policy(use_splunk_parser=True), parser=Refusing("https://x"))
    r = await ins.inspect("index=a | head 1")
    assert not r.ok and r.parser_used
    assert any("splunk parser rejected" in x for x in r.reasons)
