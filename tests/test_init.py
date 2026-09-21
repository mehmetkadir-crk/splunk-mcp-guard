import json

import pytest

from splunk_mcp_guard import init as gi
from splunk_mcp_guard.policy import load_policy


def answers(**kw):
    a = gi.Answers(principal="alice", username="mcp_svc", password="s3cret",
                   backend_command="/opt/mcp/run.sh", indexes=["main", "web"])
    for k, v in kw.items():
        setattr(a, k, v)
    return a


@pytest.mark.parametrize("profile", gi.PROFILES)
def test_home_policy_is_valid_and_scoped(tmp_path, profile):
    paths = gi.write_home(answers(profile=profile), tmp_path / "home")
    p = load_policy(paths["policy"])
    assert p.profile == profile
    for role in p.roles.values():
        assert role.indexes == ["main", "web"]
    assert paths["approvals"].is_dir()
    assert json.loads(paths["backend"].read_text())["mcpServers"]["splunk"]["command"].endswith("run.sh")


def test_existing_policy_is_not_overwritten(tmp_path):
    home = tmp_path / "home"
    paths = gi.write_home(answers(), home)
    paths["policy"].write_text(paths["policy"].read_text() + "\n# my edit\n")
    gi.write_home(answers(indexes=["other"]), home)
    assert "# my edit" in paths["policy"].read_text()


def test_backend_url_variant():
    cfg = gi.backend_config(answers(backend_command="", backend_url="http://127.0.0.1:8003/mcp"))
    assert cfg["mcpServers"]["splunk"] == {"url": "http://127.0.0.1:8003/mcp", "transport": "http"}


def test_bat_is_wrapped_on_windows(monkeypatch):
    monkeypatch.setattr(gi, "_is_windows", lambda: True)
    cfg = gi.backend_config(answers(backend_command=r"C:\mcp\run-mcp.bat"))
    s = cfg["mcpServers"]["splunk"]
    assert s["command"].lower().endswith("cmd.exe") and s["args"][0] == "/c"


def test_server_entry_uses_absolute_paths_and_credentials(tmp_path):
    paths = gi.write_home(answers(), tmp_path / "home")
    e = gi.server_entry(answers(), paths)
    assert e["env"]["GUARD_PRINCIPAL"] == "alice"
    assert e["env"]["GUARD_SPLUNK_PASSWORD"] == "s3cret"
    assert str(paths["policy"]) in e["args"] and str(paths["backend"]) in e["args"]
    assert gi._mask(e)["env"]["GUARD_SPLUNK_PASSWORD"] == "***"
    tok = gi.server_entry(answers(token="tkn", username="", password=""), paths)
    assert tok["env"]["GUARD_SPLUNK_TOKEN"] == "tkn" and "GUARD_SPLUNK_PASSWORD" not in tok["env"]


def test_unguarded_backend_is_detected_and_removed(tmp_path):
    cfg_path = tmp_path / "claude_desktop_config.json"
    cfg = {"mcpServers": {
        "splunk": {"command": "/opt/mcp/run.sh"},
        "filesystem": {"command": "npx", "args": ["@modelcontextprotocol/server-filesystem"]},
    }, "otherSetting": True}
    cfg_path.write_text(json.dumps(cfg))
    hits = gi.unguarded_splunk_servers(cfg, gi.backend_config(answers()))
    assert hits == ["splunk"]

    paths = gi.write_home(answers(), tmp_path / "home")
    backup = gi.update_client_config(cfg_path, gi.server_entry(answers(), paths), hits)
    new = json.loads(cfg_path.read_text())
    assert set(new["mcpServers"]) == {"filesystem", gi.SERVER_NAME}
    assert new["otherSetting"] is True                      # unrelated settings kept
    assert json.loads(backup.read_text()) == cfg            # backup is the original


def test_init_end_to_end_writes_config(tmp_path, monkeypatch):
    monkeypatch.setenv("GUARD_HOME", str(tmp_path / "home"))
    monkeypatch.setattr(gi, "collect_answers", lambda: answers())
    monkeypatch.setattr("builtins.input", lambda *_: "")    # accept defaults (yes)
    cfg_path = tmp_path / "cfg.json"
    rc = gi.main(["--client-config", str(cfg_path), "--skip-check"])
    assert rc == 0
    entry = json.loads(cfg_path.read_text())["mcpServers"][gi.SERVER_NAME]
    assert entry["env"]["GUARD_APPROVAL_DIR"] == str(tmp_path / "home" / "approvals")


def test_init_stops_on_overprivileged_account(tmp_path, monkeypatch):
    from splunk_mcp_guard.preflight import PreflightReport
    monkeypatch.setenv("GUARD_HOME", str(tmp_path / "home"))
    monkeypatch.setattr(gi, "collect_answers", lambda: answers())
    monkeypatch.setattr(gi, "check_account", lambda a, f: PreflightReport(
        ok=False, username="admin", roles=["admin"], offending=["can_delete"]))
    monkeypatch.setattr("builtins.input", lambda *_: "")    # default for "write anyway?" is no
    cfg_path = tmp_path / "cfg.json"
    assert gi.main(["--client-config", str(cfg_path)]) == 1
    assert not cfg_path.exists() and not (tmp_path / "home").exists()


def test_approval_cli_defaults_to_guard_home(tmp_path, monkeypatch, capsys):
    from splunk_mcp_guard.main import main
    monkeypatch.setenv("GUARD_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("GUARD_APPROVAL_DIR", raising=False)
    (tmp_path / "home" / "approvals").mkdir(parents=True)
    main(["pending"])
    assert str(tmp_path / "home" / "approvals") in capsys.readouterr().out
