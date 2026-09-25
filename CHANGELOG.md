# Changelog

## 0.1.1

Security fixes from a code review before the public announcement.

- Preflight also checks role names (`can_delete` is a role; the capability is `delete_by_keyword`), and the default list now includes `delete_by_keyword`, `edit_roles_grantable` and `change_authentication`.
- Preflight fails closed: if the account cannot be checked, the guard does not start unless `GUARD_ALLOW_OVERPRIVILEGED=1`, and an override now writes an `alert` line.
- New `spl.require_parser` (default on): a search is refused when Splunk's parser cannot be reached.
- Tokenizer: only double quotes count as quotes, ` ``` ` comments are removed, unbalanced quotes or brackets and unidentified stages are refused. Macros need the parser and are refused for roles with an index scope.
- Index scope: every search and subsearch must start with an index term that is not followed by `OR`; `tstats`/`mstats` need `where index=...`; generating commands whose index use cannot be checked are refused for scoped roles.
- Time floor: all `earliest=` / `starttime=` values are checked; epoch, absolute dates, long snaps, `rt` and long unit names are evaluated; unknown values are refused.
- `count` / `max_results` must be positive.
- More hard-denied commands: `savedsearch`, `dump`, `outputtelemetry`, `sendresults`, `dbxquery`, `dbxoutput`, `ldapmodify`, `deletemodel`.
- SPL in approve-class tools (e.g. `create_saved_search`) is inspected before asking a person; the approval prompt shows SPL first and in full.
- MCP resources and prompts from the backend are refused by default (`extras`), and filtered and logged when allowed.
- Header identity requires a shared secret from the reverse proxy (`GUARD_PROXY_SECRET`).
- Audit: secrets inside argument values (such as the SPL query) are masked; long values are kept up to 20,000 characters with a hash; inspector errors and cancelled calls are logged; each line has `"schema": 1`.
- HEC: TLS verification on by default, sent from a background thread with retries.
- Output filter: JSON-style secrets and `Basic` auth are masked; card numbers need a valid checksum, so epoch milliseconds are no longer masked.
- Approval: request ids are validated, request files are written with private permissions and redacted arguments.

Upgrading: `init` does not overwrite an existing `~/.splunk-mcp-guard/policy-*.yaml`. The new defaults apply anyway, but to get the new preflight list and comments, delete that file and run `splunk-mcp-guard init` again.

## 0.1.0

First public release.
