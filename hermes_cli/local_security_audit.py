"""Local-only host/Hermes security posture audit.

This module backs ``hermes security local-audit``. It intentionally avoids
network-backed checks: no OSV, no brew update, no softwareupdate scan, no paste
upload, no gateway send smoke test. It reports local state only, with sanitized
counts and paths.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import stat
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from hermes_constants import get_hermes_home

STATUS_ORDER = {"pass": 0, "info": 0, "warn": 1, "fail": 2}

SECRET_PATTERNS: dict[str, str] = {
    "openai_style_key": r"sk-[A-Za-z0-9_-]{20,}",
    "github_classic_token": r"ghp_[A-Za-z0-9_]{20,}",
    "github_fine_grained_token": r"github_pat_[A-Za-z0-9_]{20,}",
    "slack_token": r"xox[baprs]-[A-Za-z0-9-]{10,}",
    "aws_access_key": r"AKIA[0-9A-Z]{16}",
    "private_key_header": r"BEGIN (?:RSA|OPENSSH|DSA|EC|PRIVATE) KEY",
    "jwt": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
}

SECRET_SKIP_DIRS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    "site-packages",
    "plugin-runtime-deps",
}

# Historical/runtime stores can legitimately contain old transcripts or logs.
# Keep counting them, but do not fail recurring audits unless active/live files match.
SECRET_ARCHIVE_DIRS = {"sessions", "logs", "backups", "checkpoints", "migration"}
SECRET_ARCHIVE_PATH_PARTS = {("kanban", "workspaces")}

SENSITIVE_RELATIVE_PATHS = [
    "config.yaml",
    ".env",
    "auth.json",
    "honcho.json",
    "state.db",
]


@dataclass
class AuditSection:
    id: str
    title: str
    status: str
    summary: str
    data: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "status": self.status,
            "summary": self.summary,
            "data": self.data,
            "errors": self.errors,
        }


def _run(cmd: list[str], timeout: int = 20, env: dict[str, str] | None = None) -> dict[str, Any]:
    try:
        proc = subprocess.run(
            cmd,
            text=True,
            capture_output=True,
            timeout=timeout,
            env=env,
            check=False,
        )
        return {
            "ok": proc.returncode == 0,
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "missing": False,
        }
    except FileNotFoundError:
        return {"ok": False, "returncode": None, "stdout": "", "stderr": "missing command", "missing": True}
    except subprocess.TimeoutExpired as exc:
        return {
            "ok": False,
            "returncode": None,
            "stdout": exc.stdout or "",
            "stderr": f"timed out after {timeout}s",
            "missing": False,
        }


def _which(command: str) -> bool:
    return _run(["/usr/bin/which", command], timeout=5)["ok"]


def _parse_yaml(path: Path) -> dict[str, Any]:
    try:
        import yaml  # type: ignore
    except Exception:
        return {}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _mode_string(path: Path) -> str:
    return oct(stat.S_IMODE(path.stat().st_mode))[2:].zfill(3)


def check_os_updates() -> AuditSection:
    if platform.system() != "Darwin":
        return AuditSection(
            "SEC-001",
            "Pending OS updates",
            "info",
            "OS update check is macOS-specific; skipped on this platform.",
            {"platform": platform.system()},
        )
    if not _which("softwareupdate"):
        return AuditSection("SEC-001", "Pending OS updates", "warn", "softwareupdate command not found.")

    result = _run(["softwareupdate", "--list", "--no-scan"], timeout=60)
    text = (result["stdout"] or "") + (result["stderr"] or "")
    if "Unrecognized option" in text or "unrecognized option" in text:
        return AuditSection(
            "SEC-001",
            "Pending OS updates",
            "warn",
            "softwareupdate does not support --no-scan here; skipped to preserve local-only policy.",
            {"local_only": True},
        )
    updates = [line.strip() for line in text.splitlines() if line.strip().startswith("*")]
    if not result["ok"] and not updates:
        return AuditSection(
            "SEC-001",
            "Pending OS updates",
            "warn",
            "Could not read cached softwareupdate results.",
            {"command": "softwareupdate --list --no-scan", "returncode": result["returncode"]},
            [text.strip()[:500]] if text.strip() else [],
        )
    status = "warn" if updates else "pass"
    summary = f"{len(updates)} cached pending macOS update(s) found." if updates else "No cached pending macOS updates reported."
    return AuditSection(
        "SEC-001",
        "Pending OS updates",
        status,
        summary,
        {"count": len(updates), "updates": updates[:50], "local_only": True},
    )


def check_brew_updates() -> AuditSection:
    if not _which("brew"):
        return AuditSection("SEC-002", "Homebrew outdated packages", "info", "Homebrew not found; skipped.")
    env = os.environ.copy()
    env["HOMEBREW_NO_AUTO_UPDATE"] = "1"
    result = _run(["brew", "outdated", "--quiet"], timeout=60, env=env)
    lines = [line.strip() for line in result["stdout"].splitlines() if line.strip()]
    # `brew outdated` exits 1 when outdated formulae exist.
    if result["returncode"] not in (0, 1):
        return AuditSection(
            "SEC-002",
            "Homebrew outdated packages",
            "warn",
            "Could not read Homebrew outdated package list.",
            {"returncode": result["returncode"]},
            [result["stderr"].strip()[:500]] if result["stderr"].strip() else [],
        )
    status = "warn" if lines else "pass"
    summary = f"{len(lines)} Homebrew package(s) appear outdated." if lines else "No Homebrew outdated packages reported."
    return AuditSection(
        "SEC-002",
        "Homebrew outdated packages",
        status,
        summary,
        {"count": len(lines), "packages": lines[:200], "local_only": True, "auto_update_disabled": True},
    )


def check_listening_services() -> AuditSection:
    result = _run(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"], timeout=30)
    if result["missing"]:
        return AuditSection("SEC-003", "Listening network services", "warn", "lsof command not found.")
    if not result["ok"] and not result["stdout"].strip():
        return AuditSection(
            "SEC-003",
            "Listening network services",
            "warn",
            "Could not inspect listening TCP services.",
            {"returncode": result["returncode"]},
            [result["stderr"].strip()[:500]] if result["stderr"].strip() else [],
        )
    services: list[dict[str, Any]] = []
    for line in result["stdout"].splitlines()[1:]:
        parts = line.split()
        if len(parts) < 9:
            continue
        name, pid, user = parts[0], parts[1], parts[2]
        endpoint = parts[-2] if parts[-1] == "(LISTEN)" else parts[-1]
        bind = endpoint.rsplit(":", 1)[0]
        loopback = bind in {"127.0.0.1", "[::1]", "localhost"} or bind.endswith(".localhost")
        all_interfaces = bind in {"*", "0.0.0.0", "[::]"}
        services.append(
            {"process": name, "pid": pid, "user": user, "endpoint": endpoint, "loopback": loopback, "all_interfaces": all_interfaces}
        )
    exposed = [s for s in services if s["all_interfaces"] or not s["loopback"]]
    status = "warn" if exposed else "pass"
    summary = f"{len(services)} listener(s), {len(exposed)} non-loopback/all-interface listener(s)."
    return AuditSection(
        "SEC-003",
        "Listening network services",
        status,
        summary,
        {"listener_count": len(services), "exposed_count": len(exposed), "listeners": services[:200]},
    )


def check_secret_scan(hermes_home: Path, max_file_bytes: int = 2_000_000) -> AuditSection:
    if not hermes_home.exists():
        return AuditSection("SEC-004", "Hermes secret-scan counts", "warn", f"Hermes home not found: {hermes_home}")
    compiled = {name: re.compile(pattern) for name, pattern in SECRET_PATTERNS.items()}
    counts = {name: 0 for name in compiled}
    live_counts = {name: 0 for name in compiled}
    archive_counts = {name: 0 for name in compiled}
    files: dict[str, set[str]] = {name: set() for name in compiled}
    live_files: dict[str, set[str]] = {name: set() for name in compiled}
    archive_files: dict[str, set[str]] = {name: set() for name in compiled}
    scanned_files = 0
    skipped_large = 0

    def is_archive_path(path: Path) -> bool:
        try:
            rel_parts = path.relative_to(hermes_home).parts
        except ValueError:
            rel_parts = path.parts
        if any(part in SECRET_ARCHIVE_DIRS for part in rel_parts):
            return True
        return any(all(part in rel_parts for part in marker) for marker in SECRET_ARCHIVE_PATH_PARTS)
    for base, dirs, filenames in os.walk(hermes_home):
        dirs[:] = [d for d in dirs if d not in SECRET_SKIP_DIRS]
        for filename in filenames:
            path = Path(base) / filename
            try:
                if path.stat().st_size > max_file_bytes:
                    skipped_large += 1
                    continue
                text = path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            scanned_files += 1
            display_path = str(path)
            for name, regex in compiled.items():
                matches = regex.findall(text)
                if matches:
                    match_count = len(matches)
                    counts[name] += match_count
                    files[name].add(display_path)
                    if is_archive_path(path):
                        archive_counts[name] += match_count
                        archive_files[name].add(display_path)
                    else:
                        live_counts[name] += match_count
                        live_files[name].add(display_path)
    total = sum(counts.values())
    live_total = sum(live_counts.values())
    archive_total = sum(archive_counts.values())
    if live_total:
        status = "fail"
        summary = f"{live_total} active secret-like match(es) and {archive_total} historical match(es) found across {scanned_files} scanned file(s)."
    elif archive_total:
        status = "warn"
        summary = f"{archive_total} historical secret-like match(es) found; no active/live matches across {scanned_files} scanned file(s)."
    else:
        status = "pass"
        summary = f"No secret-like matches found across {scanned_files} scanned file(s)."
    return AuditSection(
        "SEC-004",
        "Hermes secret-scan counts",
        status,
        summary,
        {
            "root": str(hermes_home),
            "scanned_files": scanned_files,
            "skipped_large_files": skipped_large,
            "counts": counts,
            "live_counts": live_counts,
            "archive_counts": archive_counts,
            "files_by_pattern": {name: sorted(paths)[:50] for name, paths in files.items() if paths},
            "live_files_by_pattern": {name: sorted(paths)[:50] for name, paths in live_files.items() if paths},
            "archive_files_by_pattern": {name: sorted(paths)[:50] for name, paths in archive_files.items() if paths},
        },
    )


def _sensitive_paths(hermes_home: Path) -> list[Path]:
    paths = [hermes_home / rel for rel in SENSITIVE_RELATIVE_PATHS]
    paths.extend(sorted((hermes_home / "profiles").glob("*/config.yaml")))
    paths.extend(sorted((hermes_home / "profiles").glob("*/.env")))
    paths.extend(sorted((hermes_home / "profiles").glob("*/auth.json")))
    ssh = Path.home() / ".ssh"
    if ssh.exists():
        paths.extend(sorted(ssh.glob("*")))
    return [p for p in paths if p.exists()]


def check_file_modes(hermes_home: Path) -> AuditSection:
    issues: list[dict[str, str]] = []
    checked: list[dict[str, str]] = []
    for path in _sensitive_paths(hermes_home):
        try:
            mode = _mode_string(path)
        except OSError:
            continue
        kind = "dir" if path.is_dir() else "file"
        checked.append({"path": str(path), "mode": mode, "kind": kind})
        numeric = int(mode, 8)
        if path.is_dir():
            expected_max = 0o700
            has_issue = bool(numeric & 0o077)
        elif path.suffix == ".pub" or path.name == "config":
            expected_max = 0o644
            has_issue = bool(numeric & 0o022)  # writable by group/other is risky; world-readable is normal here.
        else:
            expected_max = 0o600
            has_issue = bool(numeric & 0o077)
        if has_issue:
            issues.append({"path": str(path), "mode": mode, "expected_max": oct(expected_max)[2:], "kind": kind})
    status = "fail" if issues else "pass"
    summary = f"{len(issues)} sensitive path mode issue(s) found." if issues else f"No sensitive mode issues found across {len(checked)} checked path(s)."
    return AuditSection(
        "SEC-005",
        "Sensitive file permissions",
        status,
        summary,
        {"checked_count": len(checked), "issue_count": len(issues), "issues": issues, "checked": checked[:200]},
    )


def check_gateway_status(hermes_home: Path) -> AuditSection:
    pid_file = hermes_home / "gateway.pid"
    lock_file = hermes_home / "gateway.lock"
    log_file = hermes_home / "logs" / "gateway.log"
    status_data: dict[str, Any] = {
        "pid_file_exists": pid_file.exists(),
        "lock_file_exists": lock_file.exists(),
        "log_file_exists": log_file.exists(),
    }
    running = False
    pid: int | None = None
    if pid_file.exists():
        try:
            pid = int(pid_file.read_text().strip())
            running = Path(f"/proc/{pid}").exists() if platform.system() == "Linux" else _run(["ps", "-p", str(pid), "-o", "pid="], timeout=5)["ok"]
        except Exception:
            running = False
    else:
        proc = _run(["pgrep", "-f", "hermes_cli.main gateway run|venv/bin/hermes gateway run"], timeout=5)
        running = bool(proc["stdout"].strip()) if not proc["missing"] else False
    status_data.update({"pid": pid, "running": running})
    status = "pass" if running else "warn"
    summary = "Hermes gateway appears to be running." if running else "Hermes gateway does not appear to be running."
    return AuditSection("SEC-006", "Hermes gateway status", status, summary, status_data)


def check_terminal_containerization(hermes_home: Path) -> AuditSection:
    config = _parse_yaml(hermes_home / "config.yaml")
    raw_terminal_cfg = config.get("terminal")
    terminal_cfg: dict[str, Any] = raw_terminal_cfg if isinstance(raw_terminal_cfg, dict) else {}
    backend = terminal_cfg.get("backend") or os.environ.get("TERMINAL_ENV") or os.environ.get("HERMES_TERMINAL_BACKEND")
    backend = str(backend or "unknown")
    expected = True
    containerized = backend in {"docker", "modal", "daytona", "ssh", "singularity"}
    if backend == "local":
        status = "fail"
        summary = "Terminal backend is local; expected containerized backend."
    elif backend == "unknown":
        status = "warn"
        summary = "Terminal backend could not be determined."
    elif containerized:
        status = "pass"
        summary = f"Terminal backend is {backend}."
    else:
        status = "warn"
        summary = f"Terminal backend is {backend}; containerization expectation is unclear."
    data = {
        "backend": backend,
        "expected_containerized": expected,
        "containerized": containerized,
        "cwd": terminal_cfg.get("cwd"),
        "docker_mount_cwd_to_workspace": terminal_cfg.get("docker_mount_cwd_to_workspace"),
        "docker_run_as_host_user": terminal_cfg.get("docker_run_as_host_user"),
        "docker_volumes_count": len(terminal_cfg.get("docker_volumes") or []) if isinstance(terminal_cfg.get("docker_volumes"), list) else 0,
    }
    return AuditSection("SEC-007", "Terminal backend containerization", status, summary, data)


def check_firewall_sharing() -> AuditSection:
    data: dict[str, Any] = {}
    errors: list[str] = []
    if platform.system() != "Darwin":
        return AuditSection("SEC-008", "Firewall and Sharing posture", "info", "macOS firewall/sharing checks skipped on this platform.")
    fw = _run(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate", "--getstealthmode"], timeout=20)
    data["firewall_raw"] = (fw["stdout"] + fw["stderr"]).strip()
    if not fw["ok"]:
        errors.append(data["firewall_raw"][:500])
    ssh = _run(["systemsetup", "-getremotelogin"], timeout=20)
    data["remote_login_raw"] = (ssh["stdout"] + ssh["stderr"]).strip()
    if not ssh["ok"]:
        errors.append(data["remote_login_raw"][:500])
    raw = "\n".join(str(v) for v in data.values())
    status = "warn"
    if "Firewall is enabled" in raw and "Stealth mode enabled" in raw and "Remote Login: Off" in raw:
        status = "pass"
    summary = "Firewall/sharing posture collected locally; review raw fields." if status == "warn" else "Firewall enabled, stealth mode enabled, remote login off."
    return AuditSection("SEC-008", "Firewall and Sharing posture", status, summary, data, errors)


def check_git_backup_exposure(hermes_home: Path) -> AuditSection:
    git = _run(["git", "-C", str(hermes_home), "status", "--short", "--untracked-files=all"], timeout=30)
    if git["returncode"] != 0:
        return AuditSection(
            "SEC-009",
            "Git/backup exposure posture",
            "info",
            "Hermes home is not a git repo or git status is unavailable.",
            {"root": str(hermes_home)},
        )
    risky_terms = (".env", "auth.json", "sessions/", "logs/", "state.db", "honcho.json")
    lines = [line for line in git["stdout"].splitlines() if line.strip()]
    risky = [line for line in lines if any(term in line for term in risky_terms)]
    status = "fail" if risky else "pass"
    summary = f"{len(risky)} risky git status entrie(s) detected." if risky else "No obvious risky Hermes git status entries detected."
    return AuditSection(
        "SEC-009",
        "Git/backup exposure posture",
        status,
        summary,
        {"root": str(hermes_home), "changed_entries": len(lines), "risky_entries": risky[:100]},
    )


def run_local_audit(hermes_home: Path | None = None, include_optional: bool = True) -> dict[str, Any]:
    home = hermes_home or Path(get_hermes_home())
    sections = [
        check_os_updates(),
        check_brew_updates(),
        check_listening_services(),
        check_secret_scan(home),
        check_file_modes(home),
        check_gateway_status(home),
        check_terminal_containerization(home),
    ]
    if include_optional:
        sections.extend([check_firewall_sharing(), check_git_backup_exposure(home)])
    overall = "pass"
    for section in sections:
        if STATUS_ORDER[section.status] > STATUS_ORDER[overall]:
            overall = section.status
    return {
        "tool": "hermes security local-audit",
        "local_only": True,
        "hermes_home": str(home),
        "overall_status": overall,
        "sections": [section.as_dict() for section in sections],
    }


def _render_human(report: dict[str, Any]) -> str:
    lines = [
        "Hermes local security audit",
        f"Overall: {report['overall_status'].upper()}",
        f"Hermes home: {report['hermes_home']}",
        "Local-only: yes (no remote services contacted)",
        "",
    ]
    for section in report["sections"]:
        lines.append(f"[{section['status'].upper()}] {section['id']} {section['title']}")
        lines.append(f"  {section['summary']}")
        if section.get("errors"):
            lines.append(f"  errors: {len(section['errors'])}")
        data = section.get("data") or {}
        for key in ("count", "listener_count", "exposed_count", "scanned_files", "issue_count", "running", "backend", "changed_entries"):
            if key in data:
                lines.append(f"  {key}: {data[key]}")
        lines.append("")
    return "\n".join(lines).rstrip()


def cmd_local_security_audit(args: argparse.Namespace) -> int:
    home = Path(getattr(args, "hermes_home", None) or get_hermes_home()).expanduser()
    report = run_local_audit(home, include_optional=not bool(getattr(args, "minimal", False)))
    if bool(getattr(args, "json", False)):
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(_render_human(report))
    if bool(getattr(args, "fail_on_fail", False)) and report["overall_status"] == "fail":
        return 1
    return 0


__all__ = [
    "AuditSection",
    "run_local_audit",
    "cmd_local_security_audit",
    "check_secret_scan",
    "check_file_modes",
    "check_terminal_containerization",
]
