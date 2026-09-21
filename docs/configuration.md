# Configuration reference

Everything the guard does is driven by one YAML policy file. Start from one of the shipped profiles in [`policy/`](../policy) and change what you need.

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

## Environment variables

| Variable | Purpose |
|---|---|
| `GUARD_PRINCIPAL` | Who is asking (with `identity.source: env`) |
| `GUARD_SPLUNK_HOST`, `GUARD_SPLUNK_PORT`, `GUARD_SPLUNK_SCHEME` | Splunk management endpoint for the parser and preflight (falls back to `SPLUNK_*`) |
| `GUARD_SPLUNK_TOKEN` or `GUARD_SPLUNK_USERNAME` + `GUARD_SPLUNK_PASSWORD` | Credentials for the parser and preflight |
| `GUARD_SPLUNK_VERIFY_SSL` | `false` only for lab instances with self-signed certificates |
| `GUARD_AUDIT_PATH` | Absolute path of the audit log (MCP clients start the guard from an unpredictable directory) |
| `GUARD_APPROVAL_DIR` | Absolute path of the out-of-band approval directory |
| `GUARD_ALLOW_OVERPRIVILEGED` | `1` starts the guard even if preflight finds forbidden capabilities. Emergencies only; it is logged. |
| `GUARD_HEC_TOKEN` | HEC token when `audit.hec_url` is set |

## CLI

```bash
splunk-mcp-guard --policy <file> --backend <file> [--transport stdio|http] [--host 127.0.0.1] [--port 8010]
splunk-mcp-guard --policy <file> --backend <file> --print-policy     # show the effective policy and exit
splunk-mcp-guard pending [--policy <file> | --dir <path>]
splunk-mcp-guard approve <id> [--by <name>] [--policy <file> | --dir <path>]
splunk-mcp-guard reject  <id> [--policy <file> | --dir <path>]
```
