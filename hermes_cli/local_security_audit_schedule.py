"""Local recurring scheduling for ``hermes security local-audit``.

The scheduler is intentionally local-only. On macOS it installs a per-user
launchd LaunchAgent that periodically invokes Hermes and writes timestamped
reports under the active Hermes home. It does not upload or send audit data.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import plistlib
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from hermes_constants import get_hermes_home

from hermes_cli.local_security_audit import _render_human, run_local_audit

LABEL = "ai.hermes.local-security-audit"
DEFAULT_KEEP = 12
DEFAULT_WEEKDAY = 1  # Sunday=0 in launchd, Monday=1.
DEFAULT_HOUR = 9
DEFAULT_MINUTE = 0


def default_report_dir(home: Path | None = None) -> Path:
    """Return the predictable local report directory for recurring audits."""

    base = (home or get_hermes_home()).expanduser()
    return base / "workspace" / "security-audits" / "local-recurring"


def default_launch_agent_path() -> Path:
    """Return the per-user launchd plist path."""

    return Path.home() / "Library" / "LaunchAgents" / f"{LABEL}.plist"


def _timestamp() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def _safe_report_path(report_dir: Path, suffix: str) -> Path:
    report_dir.mkdir(parents=True, exist_ok=True)
    return report_dir / f"local-security-audit-{_timestamp()}.{suffix}"


def _prune_reports(report_dir: Path, keep: int) -> list[str]:
    """Keep the newest N JSON/TXT report pairs and return removed paths."""

    if keep <= 0 or not report_dir.exists():
        return []
    candidates = sorted(
        report_dir.glob("local-security-audit-*.*"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    keep_files = keep * 2  # JSON + TXT per scheduled run.
    removed: list[str] = []
    for path in candidates[keep_files:]:
        if path.suffix not in {".json", ".txt"}:
            continue
        try:
            path.unlink()
            removed.append(str(path))
        except OSError:
            continue
    return removed


def run_scheduled_audit(
    *,
    hermes_home: Path | None = None,
    report_dir: Path | None = None,
    minimal: bool = False,
    keep: int = DEFAULT_KEEP,
) -> dict[str, Any]:
    """Run the audit once and write timestamped JSON and human reports."""

    home = (hermes_home or get_hermes_home()).expanduser()
    out_dir = (report_dir or default_report_dir(home)).expanduser()
    report = run_local_audit(home, include_optional=not minimal)
    report["scheduled_run"] = {
        "local_only": True,
        "report_dir": str(out_dir),
        "retention_keep_runs": keep,
    }

    json_path = _safe_report_path(out_dir, "json")
    txt_path = json_path.with_suffix(".txt")
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    txt_path.write_text(_render_human(report) + "\n", encoding="utf-8")
    removed = _prune_reports(out_dir, keep)

    return {
        "status": report["overall_status"],
        "json_report": str(json_path),
        "text_report": str(txt_path),
        "report_dir": str(out_dir),
        "removed_reports": removed,
    }


def _hermes_invocation() -> list[str]:
    """Build a robust local Hermes CLI invocation for LaunchAgent ProgramArguments."""

    exe = Path(sys.executable).resolve()
    if exe.name.startswith("python") or exe.name == "Python":
        return [str(exe), "-m", "hermes_cli.main"]
    return [str(exe)]


def _build_launchd_plist(
    *,
    hermes_home: Path,
    report_dir: Path,
    keep: int,
    weekday: int,
    hour: int,
    minute: int,
    minimal: bool,
) -> dict[str, Any]:
    args = [
        *_hermes_invocation(),
        "security",
        "local-audit-schedule",
        "run-once",
        "--hermes-home",
        str(hermes_home),
        "--report-dir",
        str(report_dir),
        "--keep",
        str(keep),
    ]
    if minimal:
        args.append("--minimal")

    return {
        "Label": LABEL,
        "ProgramArguments": args,
        "EnvironmentVariables": {
            "HERMES_HOME": str(hermes_home),
            "PATH": os.environ.get("PATH", "/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin"),
        },
        "StartCalendarInterval": {
            "Weekday": weekday,
            "Hour": hour,
            "Minute": minute,
        },
        "StandardOutPath": str(report_dir / "launchd.out.log"),
        "StandardErrorPath": str(report_dir / "launchd.err.log"),
        "RunAtLoad": False,
    }


def _validate_schedule(weekday: int, hour: int, minute: int, keep: int) -> None:
    if not 0 <= weekday <= 6:
        raise ValueError("weekday must be 0..6 where launchd uses Sunday=0")
    if not 0 <= hour <= 23:
        raise ValueError("hour must be 0..23")
    if not 0 <= minute <= 59:
        raise ValueError("minute must be 0..59")
    if keep < 1:
        raise ValueError("keep must be >= 1")


def install_launchd_schedule(args: argparse.Namespace) -> dict[str, Any]:
    if platform.system() != "Darwin":
        raise RuntimeError("local-audit-schedule install currently supports macOS launchd only")

    home = Path(getattr(args, "hermes_home", None) or get_hermes_home()).expanduser()
    report_dir = Path(getattr(args, "report_dir", None) or default_report_dir(home)).expanduser()
    plist_path = Path(getattr(args, "plist_path", None) or default_launch_agent_path()).expanduser()
    keep = int(getattr(args, "keep", DEFAULT_KEEP))
    weekday = int(getattr(args, "weekday", DEFAULT_WEEKDAY))
    hour = int(getattr(args, "hour", DEFAULT_HOUR))
    minute = int(getattr(args, "minute", DEFAULT_MINUTE))
    minimal = bool(getattr(args, "minimal", False))
    _validate_schedule(weekday, hour, minute, keep)

    report_dir.mkdir(parents=True, exist_ok=True)
    plist_path.parent.mkdir(parents=True, exist_ok=True)
    plist = _build_launchd_plist(
        hermes_home=home,
        report_dir=report_dir,
        keep=keep,
        weekday=weekday,
        hour=hour,
        minute=minute,
        minimal=minimal,
    )
    plist_path.write_bytes(plistlib.dumps(plist, sort_keys=True))

    loaded = False
    message = "plist written"
    if not bool(getattr(args, "no_load", False)):
        uid = os.getuid()
        subprocess.run(["launchctl", "bootout", f"gui/{uid}", str(plist_path)], check=False, capture_output=True, text=True)
        proc = subprocess.run(["launchctl", "bootstrap", f"gui/{uid}", str(plist_path)], check=False, capture_output=True, text=True)
        loaded = proc.returncode == 0
        message = "plist written and loaded" if loaded else f"plist written; launchctl bootstrap failed: {proc.stderr.strip() or proc.stdout.strip()}"

    return {
        "label": LABEL,
        "plist": str(plist_path),
        "report_dir": str(report_dir),
        "loaded": loaded,
        "schedule": {"weekday": weekday, "hour": hour, "minute": minute},
        "retention_keep_runs": keep,
        "message": message,
    }


def uninstall_launchd_schedule(args: argparse.Namespace) -> dict[str, Any]:
    plist_path = Path(getattr(args, "plist_path", None) or default_launch_agent_path()).expanduser()
    bootout_returncode = None
    if shutil.which("launchctl"):
        uid = os.getuid()
        bootout = subprocess.run(["launchctl", "bootout", f"gui/{uid}", str(plist_path)], check=False, capture_output=True, text=True)
        bootout_returncode = bootout.returncode
    existed = plist_path.exists()
    if existed:
        plist_path.unlink()
    return {
        "label": LABEL,
        "plist": str(plist_path),
        "removed_plist": existed,
        "launchctl_returncode": bootout_returncode,
    }


def schedule_status(args: argparse.Namespace) -> dict[str, Any]:
    plist_path = Path(getattr(args, "plist_path", None) or default_launch_agent_path()).expanduser()
    report_dir = Path(getattr(args, "report_dir", None) or default_report_dir()).expanduser()
    latest = sorted(report_dir.glob("local-security-audit-*.json"), key=lambda p: p.stat().st_mtime, reverse=True)[:1] if report_dir.exists() else []
    loaded = False
    if shutil.which("launchctl"):
        uid = os.getuid()
        proc = subprocess.run(["launchctl", "print", f"gui/{uid}/{LABEL}"], check=False, capture_output=True, text=True)
        loaded = proc.returncode == 0
    return {
        "label": LABEL,
        "plist": str(plist_path),
        "installed": plist_path.exists(),
        "loaded": loaded,
        "report_dir": str(report_dir),
        "latest_json_report": str(latest[0]) if latest else None,
    }


def _print_result(result: dict[str, Any], *, as_json: bool) -> None:
    if as_json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return
    for key, value in result.items():
        if isinstance(value, (dict, list)):
            print(f"{key}: {json.dumps(value, sort_keys=True)}")
        else:
            print(f"{key}: {value}")


def cmd_local_audit_schedule(args: argparse.Namespace) -> int:
    command = getattr(args, "schedule_command", None) or "status"
    try:
        if command == "run-once":
            result = run_scheduled_audit(
                hermes_home=Path(args.hermes_home).expanduser() if getattr(args, "hermes_home", None) else None,
                report_dir=Path(args.report_dir).expanduser() if getattr(args, "report_dir", None) else None,
                minimal=bool(getattr(args, "minimal", False)),
                keep=int(getattr(args, "keep", DEFAULT_KEEP)),
            )
        elif command == "install":
            result = install_launchd_schedule(args)
        elif command == "uninstall":
            result = uninstall_launchd_schedule(args)
        elif command == "status":
            result = schedule_status(args)
        else:
            raise ValueError(f"unknown local-audit-schedule command: {command}")
    except Exception as exc:
        print(f"local-audit-schedule {command} failed: {exc}", file=sys.stderr)
        return 1

    _print_result(result, as_json=bool(getattr(args, "json", False)))
    return 0


__all__ = [
    "LABEL",
    "DEFAULT_KEEP",
    "default_report_dir",
    "default_launch_agent_path",
    "run_scheduled_audit",
    "install_launchd_schedule",
    "uninstall_launchd_schedule",
    "schedule_status",
    "cmd_local_audit_schedule",
]
