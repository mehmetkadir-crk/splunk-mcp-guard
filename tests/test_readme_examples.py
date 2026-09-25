"""Every SPL example listed in README "Try it yourself" must behave as documented
under the shipped strict profile (local checks only, no Splunk needed)."""

import pytest

from splunk_mcp_guard.policy import load_policy
from splunk_mcp_guard.spl_inspector import SplInspector

from pathlib import Path

POLICY = load_policy(Path(__file__).resolve().parents[1] / "policy" / "strict.yaml")
POLICY.spl.use_splunk_parser = False  # local checks only; no Splunk in CI
ROLE = POLICY.roles["analyst"]

BLOCKED = [
    ("index=main | delete", "denied command(s): delete"),
    ("index=main | collect index=summary", "denied command(s): collect"),
    ("index=main | outputlookup users.csv", "denied command(s): outputlookup"),
    ("index=main | outputcsv dump", "denied command(s): outputcsv"),
    ('index=main | sendemail to="someone@example.com"', "denied command(s): sendemail"),
    ('index=main | map search="search index=main | delete"', "denied command(s): map"),
    ("| rest /services/authentication/users", "denied command(s): rest"),
    ("| script python evil.py", "denied command(s): script"),
    ("index=main [ search index=web | outputlookup x.csv ]", "denied command(s): outputlookup"),
    ("index=*", "wildcard index is not allowed"),
    ("index=_internal | head 5", "outside principal scope: _internal"),
    ("index=main earliest=-90d | stats count", "reaches past floor"),
    ("delete", "denied command(s): delete"),
    ("index=main OR index!=main", "must start with index"),
    ("index=main OR sourcetype=WinEventLog:Security", "must start with index"),
    ("index=main OR(sourcetype=x)", "must start with index"),
    ("index=main OR!sourcetype=x", "must start with index"),
    ("| tstats count where index=main OR(sourcetype=x)", "where index="),
    ("index=main | append [search sourcetype=linux_secure]", "must start with index"),
    ("| tstats count from datamodel=Authentication", "where index="),
    ("| loadjob scheduler__admin__search__x", "not allowed for this role"),
    ("index=main earliest=0", "reaches past floor"),
    ("index=main O'Brien | delete", "denied command(s): delete"),
    ("index=main ```c \" ``` | delete", "denied command(s): delete"),
    ("index=main | `evil`", "macros"),
    ("index=main | dbxquery connection=x query=\"DROP TABLE t\"", "dbxquery"),
]

ALLOWED = [
    "index=main | stats count by sourcetype",
    "index=wineventlog EventCode=4625 | stats count by user",
    "index=main error | head 10",
    "index=main error OR warning | head 10",
    'index=main | eval note="| delete" | table note',
]


@pytest.mark.parametrize("spl,reason", BLOCKED)
async def test_blocked_examples(spl, reason):
    r = await SplInspector(POLICY.spl, None).inspect(spl, allowed_indexes=ROLE.indexes)
    assert not r.ok and any(reason in x for x in r.reasons), r.reasons


@pytest.mark.parametrize("spl", ALLOWED)
async def test_allowed_examples(spl):
    r = await SplInspector(POLICY.spl, None).inspect(spl, allowed_indexes=ROLE.indexes)
    assert r.ok, r.reasons


async def test_keyword_at_start_is_a_search_term():
    r = await SplInspector(POLICY.spl, None).inspect("error index=main | head 10", allowed_indexes=["*"])
    assert r.ok and "error" not in r.commands
