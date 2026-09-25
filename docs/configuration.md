# Configuration reference

Everything the guard does is driven by one YAML policy file. Start from one of the shipped profiles in [`policy/`](../policy) and change what you need.

## Policy file

```yaml
version: 1
defaults: { role: analyst, unknown_tool: deny }
identity: { source: env, env_var: GUARD_PRINCIPAL }      # or source: header (see below)
preflight: { refuse_if_backend_has: [can_delete, delete_by_keyword, admin_all_objects, edit_user, edit_roles] }
spl:
  use_splunk_parser: true
  require_parser: true                                   # refuse searches when the parser is unreachable
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
principals: { alice: analyst, bob: engineer }
audit: { path: ./guard-audit.jsonl, denied_threshold: 3, window_seconds: 300,
         hec_url: null, hec_verify_tls: true, hec_ca_bundle: null, hec_index: null }
extras: { resources: deny, prompts: deny }               # MCP resources and prompts from the backend
output: { tag_untrusted: true, detect_injection: true, redact_secrets: true }
```

Precedence when a tool appears in several lists: `deny` > `approve` > `inspect` > `allow`.

## SPL inspection

Two independent views are combined; a command must be acceptable in both.

- A **local tokenizer** walks the pipeline, descends into `[ subsearches ]`, ignores quoted strings. Works offline. Cannot expand macros.
- **Splunk's parser** (`POST /services/search/parser`) expands macros and reports what would actually run. Needs a token with search access.

Hard-denied regardless of policy: `delete outputlookup outputcsv outputtext collect mcollect meventcollect tscollect summaryindex sendemail sendalert sendresults script runshellscript run map savedsearch dump outputtelemetry dbxquery dbxoutput ldapmodify deletemodel` and the `si*` summary-indexing family.

The tokenizer treats only double quotes as quotes, removes ` ``` ` comments, and refuses unbalanced quotes or brackets and stages whose command it cannot identify. Macros need the parser, and are refused for roles with an index scope.

Index scope, for roles whose `indexes` is not `["*"]`:

- every search and subsearch must start with `index=...`, `index IN (...)` or `(index=a OR index=b)`, and the next word must not be `OR` (in SPL, `index=a foo OR bar` means index a AND (foo OR bar), while `index=a OR foo` is not limited to index a);
- `tstats` / `mstats` need `where index=...` in the same form;
- `metadata`, `eventcount` and `dbinspect` must name only in-scope indexes;
- other generating commands that read events (`datamodel`, `from`, `pivot`, `loadjob`, ...) are refused.

Time floor: every `earliest=`, `starttime=` and the `earliest_time` argument is checked. Relative times, snaps to a week or longer, epoch values (`0` is all time), absolute dates and `rt` are evaluated; anything that cannot be evaluated is refused.

Result cap: `count` and `max_results` must be between 1 and `max_events`.

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
splunk-mcp-guard approve 1758400000-a1b2c3 --by alice
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

Three denials from one principal inside the window produce a `kind: alert` line. String values in `args` are checked for secrets, and values longer than 20,000 characters are cut with a sha256 of the full value. Every line has `"schema": 1`.

Set `audit.hec_url` and `GUARD_HEC_TOKEN` to also send events to Splunk HEC (`sourcetype=mcp:guard`). Sending happens in a background thread with TLS verification on (`hec_verify_tls`, `hec_ca_bundle`); events that cannot be delivered are dropped, and the local file stays complete.

## Identity in HTTP mode

With `identity.source: header` the guard reads the user from `X-Guard-Principal`, but only if the request also carries `X-Guard-Proxy-Secret` equal to the `GUARD_PROXY_SECRET` environment variable. Put an authenticating reverse proxy in front of the guard that sets both headers and strips any client-sent copies. Without the variable the guard does not start in header mode.

## Environment variables

| Variable | Purpose |
|---|---|
| `GUARD_PRINCIPAL` | Who is asking (with `identity.source: env`) |
| `GUARD_SPLUNK_HOST`, `GUARD_SPLUNK_PORT`, `GUARD_SPLUNK_SCHEME` | Splunk management endpoint for the parser and preflight (falls back to `SPLUNK_*`) |
| `GUARD_SPLUNK_TOKEN` or `GUARD_SPLUNK_USERNAME` + `GUARD_SPLUNK_PASSWORD` | Credentials for the parser and preflight |
| `GUARD_SPLUNK_VERIFY_SSL` | `false` only for lab instances with self-signed certificates |
| `GUARD_AUDIT_PATH` | Absolute path of the audit log (MCP clients start the guard from an unpredictable directory) |
| `GUARD_APPROVAL_DIR` | Absolute path of the out-of-band approval directory |
| `GUARD_ALLOW_OVERPRIVILEGED` | `1` starts the guard even if preflight fails (forbidden role or capability, or the account could not be checked). Emergencies only; it writes an `alert` line. |
| `GUARD_PROXY_SECRET` | Shared secret between the reverse proxy and the guard in header identity mode |
| `GUARD_HEC_TOKEN` | HEC token when `audit.hec_url` is set |
| `GUARD_HOME` | Where `init` keeps its files (default `~/.splunk-mcp-guard`); `pending`/`approve` use its `approvals` folder by default |

## CLI

```bash
splunk-mcp-guard init [--print] [--client-config <path>] [--skip-check]   # guided setup
splunk-mcp-guard --policy <file> --backend <file> [--transport stdio|http] [--host 127.0.0.1] [--port 8010]
splunk-mcp-guard --policy <file> --backend <file> --print-policy     # show the effective policy and exit
splunk-mcp-guard pending [--policy <file> | --dir <path>]
splunk-mcp-guard approve <id> [--by <name>] [--policy <file> | --dir <path>]
splunk-mcp-guard reject  <id> [--policy <file> | --dir <path>]
```

## Manual setup

`splunk-mcp-guard init` does all of this for you. By hand:

1. Copy a profile from `policy/` somewhere of your own and edit `indexes:` and `principals:`.
2. Describe how to start (or reach) your MCP server, like [`examples/backend.deslicer.json`](../examples/backend.deslicer.json) or [`examples/backend.remote-http.json`](../examples/backend.remote-http.json). On Windows a `.bat` file must be started through `cmd.exe /c`.
3. Add the guard to your MCP client config, like [`examples/claude_desktop_config.example.json`](../examples/claude_desktop_config.example.json). Use absolute paths everywhere; MCP clients start the guard from an unpredictable working directory.
4. Remove any other entry in the client config that reaches your Splunk MCP server directly, or the model can bypass the guard.

Claude Desktop keeps its config at:

| OS | Path |
|---|---|
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |
| Windows (Microsoft Store) | `%LOCALAPPDATA%\Packages\Claude_<id>\LocalCache\Roaming\Claude\claude_desktop_config.json` |
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Linux | `~/.config/Claude/claude_desktop_config.json` |
