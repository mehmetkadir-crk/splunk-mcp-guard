"""``splunk-mcp-guard init`` — guided setup.

Asks a few questions, then:

1. creates a per-user home (``~/.splunk-mcp-guard``) holding a copy of the chosen
   policy profile, the backend description, the audit log and the approval
   directory, so nothing depends on where the repository was cloned;
2. checks the Splunk service account (preflight) before anything is written;
3. finds the MCP client's config file (Claude Desktop on Windows, including the
   Microsoft Store build, macOS and Linux), backs it up, and adds the guard;
4. warns about any *unguarded* Splunk MCP server left in the same config,
   because a model that can reach the backend directly can bypass the guard.

Every file it touches is backed up first.  ``--print`` writes nothing to the
client config and prints the block instead, for clients other than Claude
Desktop.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import os
import shutil
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SERVER_NAME = "splunk-guarded"


def _is_windows() -> bool:
    return os.name == "nt"


PROFILES = ("strict", "engineer", "audit-only")


# ------------------------------------------------------------------ locations


def guard_home() -> Path:
    """Per-user directory for policy, backend, audit log and approvals."""
    env = os.environ.get("GUARD_HOME")
    return Path(env).expanduser() if env else Path.home() / ".splunk-mcp-guard"


def profiles_dir() -> Path | None:
    """Shipped profiles: inside the package (wheel install) or next to src/ (clone)."""
    here = Path(__file__).resolve().parent
    for cand in (here / "profiles", here.parents[1] / "policy"):
        if (cand / "strict.yaml").is_file():
            return cand
    return None


def guard_command() -> tuple[str, list[str]]:
    """How an MCP client should start the guard: the console script if it exists,
    otherwise the current interpreter with ``-m``.  Both are absolute paths."""
    exe_name = "splunk-mcp-guard.exe" if os.name == "nt" else "splunk-mcp-guard"
    script = Path(sys.executable).parent / exe_name
    if script.is_file():
        return str(script), []
    found = shutil.which("splunk-mcp-guard")
    if found:
        return str(Path(found).resolve()), []
    return sys.executable, ["-m", "splunk_mcp_guard.main"]


def client_config_candidates() -> list[Path]:
    """Claude Desktop config locations, most specific first."""
    home = Path.home()
    out: list[Path] = []
    if os.name == "nt":
        local = os.environ.get("LOCALAPPDATA")
        if local:
            # Microsoft Store (MSIX) build virtualises %APPDATA% under its package
            for pkg in sorted(Path(local, "Packages").glob("Claude_*")):
                out.append(pkg / "LocalCache" / "Roaming" / "Claude" / "claude_desktop_config.json")
        roaming = os.environ.get("APPDATA")
        if roaming:
            out.append(Path(roaming) / "Claude" / "claude_desktop_config.json")
    elif sys.platform == "darwin":
        out.append(home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json")
    else:
        out.append(home / ".config" / "Claude" / "claude_desktop_config.json")
    return out


def find_client_config() -> Path | None:
    cands = client_config_candidates()
    for p in cands:
        if p.is_file():
            return p
    for p in cands:  # app installed but never configured: its folder exists
        if p.parent.is_dir():
            return p
    return None


# ------------------------------------------------------------------ answers


@dataclass
class Answers:
    profile: str = "strict"
    principal: str = ""
    splunk_host: str = "localhost"
    splunk_port: str = "8089"
    verify_ssl: bool = True
    username: str = ""
    password: str = ""
    token: str = ""
    backend_command: str = ""          # path to the script/exe that starts the MCP server
    backend_args: list[str] = field(default_factory=list)
    backend_url: str = ""              # alternative: remote MCP server over HTTP
    indexes: list[str] = field(default_factory=list)


def _ask(prompt: str, default: str = "", secret: bool = False, optional: bool = False) -> str:
    suffix = f" [{default}]" if default and not secret else ""
    while True:
        try:
            v = getpass.getpass(f"{prompt}: ") if secret else input(f"{prompt}{suffix}: ")
        except EOFError:
            raise SystemExit("\ninput ended; setup aborted, nothing was written") from None
        v = v.strip()
        if v or default or optional:
            return v or default
        print("  (required)")


def _yes(prompt: str, default: bool = True) -> bool:
    d = "Y/n" if default else "y/N"
    try:
        v = input(f"{prompt} [{d}]: ").strip().lower()
    except EOFError:
        raise SystemExit("\ninput ended; setup aborted") from None
    return default if not v else v.startswith(("y", "e"))  # yes / evet


def collect_answers() -> Answers:
    a = Answers()
    print("\nsplunk-mcp-guard setup. Press Enter to accept the value in [brackets].\n")

    print("1) Policy profile: strict (analysts, no writes) · engineer (writes need approval) · "
          "audit-only (log only)")
    while True:
        a.profile = _ask("   profile", "strict")
        if a.profile in PROFILES:
            break
        print(f"   choose one of: {', '.join(PROFILES)}")

    a.principal = _ask("2) Your name as the guard should record it", getpass.getuser())

    print("3) Splunk management endpoint (REST, usually port 8089)")
    a.splunk_host = _ask("   host", "localhost")
    a.splunk_port = _ask("   port", "8089")
    a.verify_ssl = _yes("   verify TLS certificate? (answer no only for a lab with a self-signed cert)",
                        a.splunk_host not in {"localhost", "127.0.0.1"})

    print("4) Splunk service account (least privilege, e.g. mcp_svc). Leave the token empty to use a password.")
    a.token = _ask("   token (optional, Enter to skip)", secret=True, optional=True)
    if not a.token:
        a.username = _ask("   username", "mcp_svc")
        while not a.password:
            a.password = _ask("   password", secret=True, optional=True)

    print("5) Your Splunk MCP server")
    kind = _ask("   does the guard start it (command) or connect to it (url)?", "command").lower()
    if kind.startswith("u"):
        a.backend_url = _ask("   url", "http://127.0.0.1:8003/mcp")
    else:
        while True:
            a.backend_command = _ask("   path to the script or program that starts it "
                                     "(e.g. C:\\mcp-for-splunk\\run-mcp.bat)")
            a.backend_command = a.backend_command.strip('"')
            if Path(a.backend_command).expanduser().exists() or shutil.which(a.backend_command):
                break
            print("   not found; check the path")
        extra = _ask("   extra arguments (optional)", optional=True)
        a.backend_args = extra.split() if extra else []

    ix = _ask("6) Indexes the assistant may search, comma separated (Enter = keep profile default)",
             optional=True)
    a.indexes = [x.strip() for x in ix.split(",") if x.strip()]
    return a


# ------------------------------------------------------------------ building


def backend_config(a: Answers) -> dict[str, Any]:
    if a.backend_url:
        return {"mcpServers": {"splunk": {"url": a.backend_url, "transport": "http"}}}
    cmd = str(Path(a.backend_command).expanduser())
    args = list(a.backend_args)
    if _is_windows() and cmd.lower().endswith((".bat", ".cmd")):
        # .bat files cannot be started directly as a process on Windows
        args = ["/c", cmd, *args]
        cmd = os.environ.get("SystemRoot", r"C:\Windows").rstrip("\\") + r"\System32\cmd.exe"
    return {"mcpServers": {"splunk": {"command": cmd, "args": args}}}


def write_home(a: Answers, home: Path) -> dict[str, Path]:
    """Create the per-user home.  Existing policy is kept (it may have been edited)."""
    src = profiles_dir()
    if src is None:
        raise RuntimeError("shipped policy profiles not found; reinstall splunk-mcp-guard")
    home.mkdir(parents=True, exist_ok=True)
    (home / "approvals").mkdir(exist_ok=True)

    policy = home / f"policy-{a.profile}.yaml"
    if not policy.exists():
        text = (src / f"{a.profile}.yaml").read_text(encoding="utf-8")
        if a.indexes:
            text = _set_indexes(text, a.indexes)
        policy.write_text(text, encoding="utf-8")

    backend = home / "backend.json"
    backend.write_text(json.dumps(backend_config(a), indent=2), encoding="utf-8")
    return {"home": home, "policy": policy, "backend": backend,
            "audit": home / "guard-audit.jsonl", "approvals": home / "approvals"}


def _set_indexes(text: str, indexes: list[str]) -> str:
    """Replace every role's ``indexes:`` line with the given list (profiles keep it on one line
    or as a block; both are handled)."""
    import re
    value = "[" + ", ".join(indexes) + "]"
    lines = text.splitlines()
    out: list[str] = []
    skip_indent: int | None = None
    for line in lines:
        if skip_indent is not None:
            stripped = line.lstrip()
            # block-list items may sit at the key's own indent or deeper
            if stripped.startswith("- ") and len(line) - len(stripped) >= skip_indent:
                continue
            skip_indent = None
        m = re.match(r"^(\s*)indexes:\s*(.*)$", line)
        if m:
            indent, rest = m.group(1), m.group(2)
            out.append(f"{indent}indexes: {value}")
            if not rest or rest.startswith("#"):
                skip_indent = len(indent)
            continue
        out.append(line)
    return "\n".join(out) + "\n"


def server_entry(a: Answers, paths: dict[str, Path]) -> dict[str, Any]:
    cmd, pre = guard_command()
    env = {
        "PYTHONIOENCODING": "utf-8",
        "PYTHONUTF8": "1",
        "GUARD_PRINCIPAL": a.principal,
        "GUARD_AUDIT_PATH": str(paths["audit"]),
        "GUARD_APPROVAL_DIR": str(paths["approvals"]),
        "GUARD_SPLUNK_HOST": a.splunk_host,
        "GUARD_SPLUNK_PORT": a.splunk_port,
        "GUARD_SPLUNK_VERIFY_SSL": "true" if a.verify_ssl else "false",
    }
    if a.token:
        env["GUARD_SPLUNK_TOKEN"] = a.token
    else:
        env["GUARD_SPLUNK_USERNAME"] = a.username
        env["GUARD_SPLUNK_PASSWORD"] = a.password
    return {"command": cmd,
            "args": [*pre, "--policy", str(paths["policy"]), "--backend", str(paths["backend"])],
            "env": env}


def unguarded_splunk_servers(cfg: dict[str, Any], backend: dict[str, Any]) -> list[str]:
    """Entries in the client config that reach Splunk without the guard."""
    target = json.dumps(backend.get("mcpServers", {}).get("splunk", {}), sort_keys=True).lower()
    hits = []
    for name, entry in (cfg.get("mcpServers") or {}).items():
        if name == SERVER_NAME:
            continue
        blob = json.dumps(entry, sort_keys=True).lower()
        if "splunk" in name.lower() or "splunk" in blob or blob == target:
            hits.append(name)
    return hits


def update_client_config(path: Path, entry: dict[str, Any], remove: list[str]) -> Path | None:
    """Back up, add/replace the guard entry, drop *remove*.  Returns the backup path."""
    cfg: dict[str, Any] = {}
    backup = None
    if path.is_file():
        raw = path.read_text(encoding="utf-8-sig")
        cfg = json.loads(raw) if raw.strip() else {}
        backup = path.with_name(f"{path.name}.{time.strftime('%Y%m%d-%H%M%S')}.bak")
        shutil.copy2(path, backup)
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
    servers = cfg.setdefault("mcpServers", {})
    for name in remove:
        servers.pop(name, None)
    servers[SERVER_NAME] = entry
    path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False), encoding="utf-8")
    return backup


def _mask(entry: dict[str, Any]) -> dict[str, Any]:
    e = json.loads(json.dumps(entry))
    for k in ("GUARD_SPLUNK_PASSWORD", "GUARD_SPLUNK_TOKEN"):
        if k in e.get("env", {}):
            e["env"][k] = "***"
    return e


# ------------------------------------------------------------------ preflight


def check_account(a: Answers, forbidden: list[str]):
    from .preflight import check_backend_account
    return asyncio.run(check_backend_account(
        f"https://{a.splunk_host}:{a.splunk_port}", token=a.token or None,
        username=a.username or None, password=a.password or None,
        verify_ssl=a.verify_ssl, forbidden=forbidden,
    ))


# ------------------------------------------------------------------ CLI


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="splunk-mcp-guard init",
                                 description="Guided setup: policy, backend, Splunk account, client config.")
    ap.add_argument("--client-config", help="path of the MCP client config to update "
                                            "(default: Claude Desktop, detected)")
    ap.add_argument("--print", dest="print_only", action="store_true",
                    help="do not touch any client config; print the block to paste instead")
    ap.add_argument("--skip-check", action="store_true", help="do not contact Splunk during setup")
    ns = ap.parse_args(argv)

    a = collect_answers()
    home = guard_home()

    # 1) account check before anything is written
    if not ns.skip_check:
        from .policy import load_policy
        src = profiles_dir()
        forbidden = load_policy(src / f"{a.profile}.yaml").preflight.refuse_if_backend_has if src else []
        print("\nChecking the Splunk account …")
        rep = check_account(a, forbidden)
        if rep.error:
            print(f"  could not check: {rep.error}")
            if not _yes("  continue anyway?", False):
                return 1
        elif rep.offending:
            print(f"  account {rep.username!r} (roles {rep.roles}) holds {rep.offending}.")
            print("  The guard will refuse to start with this account. Create a least-privilege account "
                  "(see README, 'Create a least-privilege Splunk account') and run init again.")
            if not _yes("  write the configuration anyway?", False):
                return 1
        else:
            print(f"  ok: {rep.username!r}, roles {rep.roles}, no forbidden capabilities")

    # 2) per-user home
    paths = write_home(a, home)
    entry = server_entry(a, paths)
    print(f"\nFiles in {home}:")
    for k in ("policy", "backend", "audit", "approvals"):
        print(f"  {k:10} {paths[k]}")

    # 3) client config
    block = {"mcpServers": {SERVER_NAME: entry}}
    if ns.print_only:
        print("\nAdd this to your MCP client's config (password shown in full, keep it private):\n")
        print(json.dumps(block, indent=2, ensure_ascii=False))
        return 0

    cfg_path = Path(ns.client_config).expanduser() if ns.client_config else find_client_config()
    if cfg_path is None:
        print("\nClaude Desktop config not found. Paste this into your MCP client's config:\n")
        print(json.dumps(block, indent=2, ensure_ascii=False))
        return 0

    existing: dict[str, Any] = {}
    if cfg_path.is_file():
        try:
            raw = cfg_path.read_text(encoding="utf-8-sig")
            existing = json.loads(raw) if raw.strip() else {}
        except ValueError as e:
            print(f"\n{cfg_path} is not valid JSON ({e}); fix it or use --print.")
            return 1

    remove: list[str] = []
    bypass = unguarded_splunk_servers(existing, backend_config(a))
    if bypass:
        print(f"\nThe client config also has {bypass}, which reach Splunk WITHOUT the guard.")
        print("The model could use those instead and bypass every rule.")
        if _yes("Remove them (a backup is kept)?", True):
            remove = bypass

    print(f"\nWill update {cfg_path}")
    print(json.dumps({"mcpServers": {SERVER_NAME: _mask(entry)}}, indent=2, ensure_ascii=False))
    if not _yes("Write it?", True):
        return 1
    backup = update_client_config(cfg_path, entry, remove)
    print(f"\nDone. Backup: {backup or '(new file)'}")
    print("Note: the Splunk password/token is stored in that config file, readable by your user account.")
    print("\nNext: fully quit and reopen Claude Desktop, then ask it to list Splunk indexes.")
    print(f"Pending approvals:  splunk-mcp-guard pending")
    print(f"Edit your policy:   {paths['policy']}")
    return 0
