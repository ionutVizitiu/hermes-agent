"""Unit tests for hermes_cli.local_security_audit.

These tests keep the audit local/deterministic: shell probes are monkeypatched
or limited to temp files, and no network-backed update checks run.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from hermes_cli import local_security_audit as lsa


def test_secret_scan_counts_patterns_without_values(tmp_path: Path):
    token_file = tmp_path / "config.yaml"
    token_file.write_text("token sk-" + "A" * 30 + "\n", encoding="utf-8")

    section = lsa.check_secret_scan(tmp_path)

    assert section.status == "fail"
    assert section.data["counts"]["openai_style_key"] == 1
    assert section.data["live_counts"]["openai_style_key"] == 1
    encoded = json.dumps(section.as_dict())
    assert "sk-" + "A" * 30 not in encoded
    assert str(token_file) in encoded


def test_secret_scan_historical_sessions_warn_without_values(tmp_path: Path):
    (tmp_path / "sessions").mkdir()
    token_file = tmp_path / "sessions" / "s.jsonl"
    token_file.write_text("token sk-" + "A" * 30 + "\n", encoding="utf-8")

    section = lsa.check_secret_scan(tmp_path)

    assert section.status == "warn"
    assert section.data["counts"]["openai_style_key"] == 1
    assert section.data["archive_counts"]["openai_style_key"] == 1
    assert section.data["live_counts"]["openai_style_key"] == 0
    encoded = json.dumps(section.as_dict())
    assert "sk-" + "A" * 30 not in encoded
    assert str(token_file) in encoded


def test_file_modes_flags_group_or_world_permissions(tmp_path: Path):
    cfg = tmp_path / "config.yaml"
    env = tmp_path / ".env"
    cfg.write_text("model: {}\n", encoding="utf-8")
    env.write_text("EXAMPLE=1\n", encoding="utf-8")
    cfg.chmod(0o600)
    env.chmod(0o644)

    section = lsa.check_file_modes(tmp_path)

    assert section.status == "fail"
    assert section.data["issue_count"] >= 1
    assert any(issue["path"] == str(env) and issue["mode"] == "644" for issue in section.data["issues"])


def test_terminal_containerization_from_config(tmp_path: Path):
    (tmp_path / "config.yaml").write_text("terminal:\n  backend: docker\n", encoding="utf-8")

    section = lsa.check_terminal_containerization(tmp_path)

    assert section.status == "pass"
    assert section.data["backend"] == "docker"
    assert section.data["containerized"] is True


def test_terminal_containerization_fails_for_local_backend(tmp_path: Path):
    (tmp_path / "config.yaml").write_text("terminal:\n  backend: local\n", encoding="utf-8")

    section = lsa.check_terminal_containerization(tmp_path)

    assert section.status == "fail"
    assert "expected containerized" in section.summary


def test_run_local_audit_renders_required_sections(monkeypatch, tmp_path: Path):
    def sec(id_: str, status: str = "pass") -> lsa.AuditSection:
        return lsa.AuditSection(id_, f"title {id_}", status, f"summary {id_}")

    monkeypatch.setattr(lsa, "check_os_updates", lambda: sec("SEC-001"))
    monkeypatch.setattr(lsa, "check_brew_updates", lambda: sec("SEC-002", "warn"))
    monkeypatch.setattr(lsa, "check_listening_services", lambda: sec("SEC-003"))
    monkeypatch.setattr(lsa, "check_secret_scan", lambda home: sec("SEC-004"))
    monkeypatch.setattr(lsa, "check_file_modes", lambda home: sec("SEC-005"))
    monkeypatch.setattr(lsa, "check_gateway_status", lambda home: sec("SEC-006"))
    monkeypatch.setattr(lsa, "check_terminal_containerization", lambda home: sec("SEC-007"))

    report = lsa.run_local_audit(tmp_path, include_optional=False)

    assert report["local_only"] is True
    assert report["overall_status"] == "warn"
    assert [section["id"] for section in report["sections"]] == [
        "SEC-001",
        "SEC-002",
        "SEC-003",
        "SEC-004",
        "SEC-005",
        "SEC-006",
        "SEC-007",
    ]


def test_cmd_json_exit_code_only_fails_with_flag(monkeypatch, tmp_path: Path, capsys):
    report = {
        "tool": "hermes security local-audit",
        "local_only": True,
        "hermes_home": str(tmp_path),
        "overall_status": "fail",
        "sections": [],
    }
    monkeypatch.setattr(lsa, "run_local_audit", lambda home, include_optional=True: report)

    args = argparse.Namespace(json=True, minimal=False, fail_on_fail=False, hermes_home=str(tmp_path))
    assert lsa.cmd_local_security_audit(args) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["overall_status"] == "fail"

    args.fail_on_fail = True
    assert lsa.cmd_local_security_audit(args) == 1
