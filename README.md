# splunk-mcp-guard

**A security proxy between AI assistants and Splunk.** It sits in front of any Splunk MCP server and decides, for every call, whether the assistant may run it.

[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)

> Not affiliated with Splunk LLC or Cisco. It adds a layer on top of Splunk RBAC; it does not replace it.

## The problem

Splunk MCP servers connect with a single Splunk account. Whatever that account can do, the AI assistant can do, and so can everyone who uses the assistant. One search tool that accepts raw SPL is enough to run `| delete`, `| collect` or `| sendemail`.

The guard stops three things that go wrong in practice:

| Situation | What the guard does |
|---|---|
| The service account has more rights than it should | Checks the account at startup and **refuses to run** if it holds `can_delete`, `admin_all_objects`, and similar capabilities |
| The model makes a mistake or is manipulated by text in the logs | **Inspects every search** and blocks destructive commands; **write actions need a human** to approve them |
| A user asks for data outside their scope | Maps each person to a role with its own tools and indexes; the request is **denied, logged**, and repeated attempts raise an **alert** |

## How it works

![How splunk-mcp-guard handles a tool call](docs/how-it-works.svg)

Each call passes four checks: **identity → role**, **tool class**, **SPL inspection** and **human approval**. If any check fails, the client gets an error and nothing reaches Splunk. Calls that pass go to the real MCP server. Results come back as untrusted data, pass through the **output guard**, and every decision goes to the **audit log**.

## Quick start

**Requirements:** Python 3.10+, a working Splunk MCP server (tested with [deslicer/mcp-for-splunk](https://github.com/deslicer/mcp-for-splunk)), and an MCP client such as Claude Desktop.

### 1. Install

```bash
git clone https://github.com/mehmetkadir-crk/splunk-mcp-guard.git
cd splunk-mcp-guard
python -m venv .venv
source .venv/bin/activate          # Windows: .\.venv\Scripts\Activate.ps1
pip install -e .
```

### 2. Create a least-privilege Splunk account

In Splunk Web:

1. **Settings → Roles → New Role:** name it `mcp_reader`, inherit only `user`, add no capabilities.
2. **Settings → Users → New User:** name it `mcp_svc` and assign only `mcp_reader`.

Use this account for both the MCP server and the guard. With an admin account the guard refuses to start. That refusal is intended.

### 3. Point the guard at your MCP server

Copy [`examples/backend.deslicer.json`](examples/backend.deslicer.json) and set the command that starts your MCP server:

```json
{"mcpServers": {"splunk": {"command": "/path/to/start-your-mcp-server"}}}
```

### 4. Choose a policy

Start with [`policy/strict.yaml`](policy/strict.yaml). Edit the `indexes:` list under `roles: analyst:` and map your users under `principals:`.

### 5. Connect your MCP client

Add the guard to your client config instead of the MCP server. For Claude Desktop, see [`examples/claude_desktop_config.example.json`](examples/claude_desktop_config.example.json):

```json
{
  "mcpServers": {
    "splunk-guarded": {
      "command": "/path/to/splunk-mcp-guard/.venv/bin/splunk-mcp-guard",
      "args": ["--policy", "/path/to/policy/strict.yaml",
               "--backend", "/path/to/backend.json"],
      "env": {
        "GUARD_PRINCIPAL": "alice",
        "GUARD_SPLUNK_HOST": "localhost",
        "GUARD_SPLUNK_USERNAME": "mcp_svc",
        "GUARD_SPLUNK_PASSWORD": "<password>",
        "GUARD_AUDIT_PATH": "/path/to/guard-audit.jsonl",
        "GUARD_APPROVAL_DIR": "/path/to/guard-approvals"
      }
    }
  }
}
```

### 6. Verify

Restart the client and ask it to list indexes. The result should carry a `_guard` notice, and `guard-audit.jsonl` should show a `preflight` line with `ok: true`. Then ask it to run `index=main | delete`. The guard should reject it.

## Policy profiles

| Profile | Use it for | Searches | Write actions | Delete actions |
|---|---|---|---|---|
| [`audit-only`](policy/audit-only.yaml) | Seeing what an existing setup actually does | allowed, logged | allowed, logged | allowed, logged |
| [`strict`](policy/strict.yaml) | Analysts | inspected, command allowlist | blocked | blocked |
| [`engineer`](policy/engineer.yaml) | Engineers who build searches and alerts | inspected | **human approval** | blocked |

If you already have an assistant connected to Splunk, start with `audit-only`, review the log, then switch to `strict` or `engineer`.

## Approving write actions

When a tool needs approval, the guard first asks through the MCP client. Many clients, Claude Desktop included, cannot show that prompt yet. In that case the guard waits up to 120 seconds for approval from a terminal:

```bash
splunk-mcp-guard pending --dir /path/to/guard-approvals
splunk-mcp-guard approve <id> --by alice --dir /path/to/guard-approvals
```

If nobody approves in time, the answer is no. Keep the approval directory where the assistant's own tools cannot write.

## Limitations

- It cannot see inside a saved search, so running saved searches is blocked in `strict` and needs approval in `engineer`.
- Secret redaction and prompt-injection detection use patterns. They make cheap attacks harder but are not a guarantee.
- In HTTP mode the guard does not authenticate users itself. Put an authenticating proxy in front of it.

## Documentation

- [Configuration reference](docs/configuration.md): policy format, SPL rules, approval modes, audit format, environment variables, CLI
- [Live verification](docs/verification.md): what was tested against a real Splunk instance and the results
- [Security policy](SECURITY.md): how to report a vulnerability
- **Türkçe:** [Nasıl çalışır](docs/nasil-calisir.md) · [Akış şeması](docs/calisma-mantigi.svg)

## Development

```bash
pip install -e ".[dev]"
pytest
```

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
