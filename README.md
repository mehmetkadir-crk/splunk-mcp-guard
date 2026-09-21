# splunk-mcp-guard

A policy-enforcing proxy that sits **in front of any Splunk MCP server** and decides, per person and per call, what the model may do.

```
LLM client ──► splunk-mcp-guard ──► Splunk MCP server ──► Splunk
                    │                (deslicer, official app, …)
                    ├─ tool policy      allow / inspect / approve / deny, per role
                    ├─ SPL inspection   Splunk's own parser + command allowlist + limits
                    ├─ human approval   elicitation before any write
                    ├─ preflight        refuses to start on an over-privileged account
                    ├─ output guard     results tagged as untrusted data, secrets redacted
                    └─ audit            one JSON line per decision, denial-rate alerts
```

> **Not affiliated with Splunk LLC or Cisco.** "Splunk" is used only to describe compatibility.
> This is a defense-in-depth layer. It does not replace Splunk RBAC; it assumes RBAC will one day be misconfigured and plans for that.

## Why

Connecting an LLM to a SIEM through MCP usually means one static account in a `.env` file. Whatever that account can do, the model can do, and every user of the assistant inherits it. Tool lists look granular, but a single `run_search` tool that accepts raw SPL can `| delete`, `| outputlookup`, `| collect` or `| sendemail`. The guard closes that gap without forking the server you already use.

It handles three failure modes that look identical in the audit log but have different causes:

| Cause | What the guard does |
|---|---|
| The backend account is over-privileged and nobody noticed | **Preflight** queries `/services/authentication/current-context` at startup and refuses to run if the account holds `can_delete`, `admin_all_objects`, … |
| The model is manipulated (prompt injection through log content) or simply wrong | **Policy + inspection** decide per tool and per SPL command; writes need a **human** to click approve; results are **tagged** as data and scanned for instruction-shaped text |
| A restricted user asks for something outside their scope | **Identity** maps each principal to a role with its own tool set and index scope; the attempt is **denied and audited**, and repeated attempts raise an **alert** |

## Install

```bash
pip install splunk-mcp-guard        # or: pip install -e . from a clone
```

Requires Python 3.10+ and a Splunk MCP server to wrap (tested with [deslicer/mcp-for-splunk](https://github.com/deslicer/mcp-for-splunk)).

## Quick start

1. Describe the backend as a normal MCP config (`examples/backend.deslicer.json`):

   ```json
   {"mcpServers": {"splunk": {"command": "uv", "args": ["--directory", "/path/to/mcp-for-splunk", "run", "fastmcp", "run", "src/server.py"]}}}
   ```

2. Pick a policy profile (`policy/strict.yaml` to start) and set who you are:

   ```bash
   export GUARD_PRINCIPAL=ahmet          # who is asking
   export GUARD_SPLUNK_HOST=localhost    # for the SPL parser and preflight
   export GUARD_SPLUNK_TOKEN=...         # a read-only token is enough
   export GUARD_SPLUNK_VERIFY_SSL=false  # lab only
   ```

3. Point your MCP client at the guard instead of the server (`examples/claude_desktop_config.example.json`):

   ```json
   {"mcpServers": {"splunk-guarded": {
     "command": "splunk-mcp-guard",
     "args": ["--policy", "policy/strict.yaml", "--backend", "examples/backend.deslicer.json"]}}}
   ```

The guard starts the backend, filters its tool list, and mediates every call.

## Profiles

| Profile | Default role | Searches | Writes | Deletes / `.conf` writes | Unknown tools |
|---|---|---|---|---|---|
| `strict` | analyst | inspected, **command allowlist** | denied | denied | denied |
| `engineer` | engineer | inspected, denylist only | **human approval** | denied | denied |
| `audit-only` | observer | forwarded | forwarded | forwarded | allowed |

Start with `audit-only` on an existing deployment to see what the assistant really does, then move to `engineer` or `strict`.

## Policy file

```yaml
version: 1
defaults: { role: analyst, unknown_tool: deny }
identity: { source: env, env_var: GUARD_PRINCIPAL }      # or header: X-Guard-Principal
preflight: { refuse_if_backend_has: [can_delete, admin_all_objects] }
spl:
  use_splunk_parser: true
  allowed_commands: [search, stats, table, …]            # empty = denylist mode
  max_events: 1000
  earliest_floor: "-30d"
  forbid_wildcard_index: true
roles:
  analyst:
    indexes: [wineventlog, sysmon, proxy]                # per-role index scope
    tools:
      allow:   [list_indexes, get_metadata, …]
      inspect: [run_splunk_search, run_oneshot_search]
      approve: []
      deny:    [delete_saved_search, create_config, manage_apps, …]
    spl_args: { run_splunk_search: [query] }
principals: { ahmet: analyst, kadir: engineer }
audit: { path: ./guard-audit.jsonl, denied_threshold: 3, window_seconds: 300 }
output: { tag_untrusted: true, detect_injection: true, redact_secrets: true }
```

Precedence when a tool appears in several lists: `deny` > `approve` > `inspect` > `allow`.

## SPL inspection

Two independent views are combined; a command must be acceptable in both.

- A **local tokenizer** walks the pipeline, descends into `[ subsearches ]`, ignores quoted strings. Works offline. Cannot expand macros.
- **Splunk's parser** (`POST /services/search/parser`) expands macros and reports what would actually run. Needs a token with search access.

Hard-denied regardless of policy: `delete outputlookup outputcsv collect mcollect meventcollect tscollect summaryindex sendemail sendalert script runshellscript run map` and the `si*` summary-indexing family.

Also enforced: index scope per role, `index=*` ban, `earliest` floor (relative times), result cap.

> Verify on your Splunk version that the parser response flattens subsearch commands; the local tokenizer covers them either way.

## Human approval

`approve`-class tools need an explicit yes from a person. Two ways to get one, selected by `approval.mode`:

| mode | What happens |
|---|---|
| `elicit` | MCP **elicitation**: the client shows the person the tool name and arguments and asks. Clients without elicitation (Claude Desktop answers `Method not found` at the time of writing) make `approve` behave like `deny`. |
| `file` | **Out-of-band**: the guard writes `<approval.dir>/<id>.request.json` and waits up to `timeout_seconds`. A person runs `splunk-mcp-guard approve <id>` (or `reject`) in a terminal. |
| `auto` (default) | Try elicitation; if the client cannot elicit, fall back to the directory. A person declining through the client is final. |

```bash
splunk-mcp-guard pending --policy policy/engineer.yaml     # what is waiting
splunk-mcp-guard approve 1758400000-a1b2c3 --by kadir
splunk-mcp-guard reject  1758400000-a1b2c3
```

Everything that is not an explicit yes — no support, decline, cancel, timeout, unreadable decision, id mismatch — is a **no**, audited as `approve-deny`.

> **Trust boundary.** Whoever can write to `approval.dir` is the approver. Keep it outside any folder the model's own tools can write to; an agent with shell access there could approve itself. `GUARD_APPROVAL_DIR` overrides the path from the environment.

## Audit

One JSON line per decision:

```json
{"ts": 1758400000.1, "kind": "decision", "principal": "junior", "role": "analyst",
 "tool": "run_splunk_search", "decision": "inspect-deny",
 "reason": "index(es) outside principal scope: hr_app", "args": {"query": "index=hr_app | head 5"}}
```

Three denials from one principal inside the window produce a `kind: alert` line. Set `audit.hec_url` and `GUARD_HEC_TOKEN` to ship events to Splunk itself and alert on `sourcetype=mcp:guard`.

## Verified against a live Splunk

Splunk Enterprise 10 (single instance), deslicer/mcp-for-splunk as backend, Claude Desktop as client, `strict` profile, backend account `mcp_svc` with a custom `mcp_reader` role (inherits `user`, no `can_delete`/`admin_all_objects`):

| Test | Result |
|---|---|
| Startup with an admin backend account | refused (`offending: [admin_all_objects, edit_roles, edit_user]`); `mcp_svc` passes with `offending: []` |
| `tools/list` | 41 of 57 tools visible; every write/delete tool hidden |
| `index=main earliest=-1h \| delete` | rejected by both the local tokenizer and Splunk's parser (`insufficient privileges to delete events`) |
| `\| outputlookup` inside a `[subsearch]` | rejected |
| `index=*` | rejected |
| `index=_internal` outside the role's scope | rejected **before** reaching Splunk |
| three denials in five minutes | `kind: alert` line written |
| `create_saved_search` under `engineer`, client without elicitation | `approve-deny` (fail closed); with `mode: auto` the request waits in the approval directory instead |
| Structured tool results | `_guard` notice attached, secrets redacted in both text and structured channels |

A Splunk RBAC detail worth knowing: a role that inherits `user` inherits `srchIndexesAllowed = *`, so the indexes you tick on your custom role are *added* to that, not a narrowing. The guard's per-role `indexes:` list is the narrowing.

## What this does not do

- It cannot see inside a saved search, so `execute_saved_search` is `deny` in strict and `approve` in engineer.
- Out-of-band approval is only as strong as the write permissions on the approval directory.
- Output redaction and injection detection are pattern-based. They raise the cost of cheap attacks; they are not a filter you can rely on.
- The parser needs credentials. Without them the local tokenizer still runs, and the audit line says so.
- If you bind HTTP to anything but loopback, put an authenticating proxy in front and use `identity.source: header`.

## Development

```bash
pip install -e ".[dev]"
pytest
splunk-mcp-guard --policy policy/strict.yaml --backend examples/backend.deslicer.json --print-policy
```

## License

Apache-2.0. See `LICENSE` and `NOTICE`.

---

## Türkçe özet

`splunk-mcp-guard`, herhangi bir Splunk MCP sunucusunun önüne konan bir güvenlik katmanı. Kimin sorduğunu bilir, her tool çağrısını politikaya göre sınıflandırır (izin / denetle / onay iste / reddet), SPL'i Splunk'ın kendi parser'ıyla açıp yıkıcı komutları yakalar, yazma işlemleri için insandan onay ister, sonuçları "bu veridir, talimat değildir" diye etiketler ve her kararı denetim kaydına yazar.

Üç durumu ayrı ayrı ele alır: yetkisi fazla verilmiş bir hesap (açılışta reddeder), manipüle edilmiş ya da hata yapan bir model (politika ve denetim), yetkisinin dışına çıkmaya çalışan kısıtlı bir kullanıcı (reddeder, kaydeder, tekrarında alarm üretir).

Splunk RBAC'ın yerine geçmez; RBAC'ın bir gün yanlış yapılandırılacağını varsayar ve ona göre tasarlanmıştır.
