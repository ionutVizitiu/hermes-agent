"""Unit tests for recurring local security audit scheduling."""

from __future__ import annotations

import argparse
import json
import plistlib
from pathlib import Path

from hermes_cli import local_security_audit_schedule as sched
from hermes_cli.local_security_audit import AuditSection


def test_run_scheduled_audit_writes_timestamped_json_and_text(monkeypatch, tmp_path: Path):
    home = tmp_path / "home"
    report_dir = tmp_path / "reports"
    home.mkdir()

    report = {
        "tool": "hermes security local-audit",
        "local_only": True,
        "hermes_home": str(home),
        "overall_status": "warn",
        "sections": [AuditSection("SEC-001", "updates", "warn", "cached update check").as_dict()],
    }
    monkeypatch.setattr(sched, "run_local_audit", lambda audit_home, include_optional=True: report)

    result = sched.run_scheduled_audit(hermes_home=home, report_dir=report_dir, minimal=True, keep=12)

    json_path = Path(result["json_report"])
    txt_path = Path(result["text_report"])
    assert json_path.exists()
    assert txt_path.exists()
    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert data["overall_status"] == "warn"
    assert data["scheduled_run"]["local_only"] is True
    assert data["scheduled_run"]["retention_keep_runs"] == 12
    assert "Hermes local security audit" in txt_path.read_text(encoding="utf-8")


def test_prune_reports_keeps_newest_run_pairs(tmp_path: Path):
    report_dir = tmp_path / "reports"
    report_dir.mkdir()
    for i in range(3):
        for suffix in ("json", "txt"):
            path = report_dir / f"local-security-audit-2026010{i}-090000.{suffix}"
            path.write_text("{}", encoding="utf-8")

    removed = sched._prune_reports(report_dir, keep=1)

    assert len(removed) == 4
    assert len(list(report_dir.glob("local-security-audit-*.*"))) == 2


def test_install_launchd_schedule_writes_plist_without_loading(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(sched.platform, "system", lambda: "Darwin")
    home = tmp_path / "home"
    report_dir = tmp_path / "reports"
    plist_path = tmp_path / "LaunchAgents" / "ai.hermes.local-security-audit.plist"
    home.mkdir()
    args = argparse.Namespace(
        hermes_home=str(home),
        report_dir=str(report_dir),
        plist_path=str(plist_path),
        keep=8,
        weekday=2,
        hour=10,
        minute=30,
        minimal=True,
        no_load=True,
    )

    result = sched.install_launchd_schedule(args)

    assert result["loaded"] is False
    assert plist_path.exists()
    plist = plistlib.loads(plist_path.read_bytes())
    assert plist["Label"] == sched.LABEL
    assert plist["StartCalendarInterval"] == {"Hour": 10, "Minute": 30, "Weekday": 2}
    assert plist["EnvironmentVariables"]["HERMES_HOME"] == str(home)
    assert "local-audit-schedule" in plist["ProgramArguments"]
    assert "run-once" in plist["ProgramArguments"]
    assert "--minimal" in plist["ProgramArguments"]
    assert str(report_dir / "launchd.out.log") == plist["StandardOutPath"]


def test_install_rejects_invalid_retention(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(sched.platform, "system", lambda: "Darwin")
    args = argparse.Namespace(
        hermes_home=str(tmp_path),
        report_dir=str(tmp_path / "reports"),
        plist_path=str(tmp_path / "job.plist"),
        keep=0,
        weekday=1,
        hour=9,
        minute=0,
        minimal=False,
        no_load=True,
    )

    try:
        sched.install_launchd_schedule(args)
    except ValueError as exc:
        assert "keep" in str(exc)
    else:
        raise AssertionError("expected invalid keep to raise")
