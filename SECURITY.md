# Security Policy

## Scope

splunk-mcp-guard is a defense-in-depth layer. Findings that matter most:

- a way to get a hard-denied SPL command (`delete`, `outputlookup`, `collect`, `sendemail`, …) past the inspector
- a way to call a `deny`- or `approve`-class tool without the policy noticing (tool name aliasing, prefixing, list/call mismatch)
- a way to make the guard fail **open** (parser outage, elicitation error, audit write failure) instead of closed
- identity spoofing in `header` mode

Out of scope: weaknesses in the wrapped MCP server or in Splunk itself, and pattern-based output redaction bypasses (documented as best-effort).

## Reporting

Open a private security advisory on the GitHub repository, or email the maintainer address listed in `pyproject.toml`. Please include the policy file, the tool call (with arguments) and the audit line that was produced.

Expect an acknowledgement within 7 days. Fixed issues are credited in the changelog unless you ask otherwise.

## Design commitments

- Every failure path defaults to **deny**.
- No telemetry, no phone-home, no default credentials.
- The audit log is append-only from the guard's point of view; rotate and protect it like any other security log.
