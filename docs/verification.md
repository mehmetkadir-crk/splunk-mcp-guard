# Live verification

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
