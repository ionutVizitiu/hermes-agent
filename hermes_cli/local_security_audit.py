"""Local-only host/Hermes security posture audit.

This module backs ``hermes security local-audit``. It intentionally avoids
network-backed checks: no OSV, no brew update, no softwareupdate scan, no paste
upload, no gateway send smoke test. It reports local state only, with sanitized
counts and paths. The tailnet sections (SEC-010, SEC-011) talk only to this
machine: the local tailscaled, and its own tailnet name for the login probes.
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import platform
import re
import shutil
import ssl
import stat
import subprocess
import sys
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from hermes_constants import get_hermes_home

STATUS_ORDER = {"pass": 0, "info": 0, "warn": 1, "fail": 2}

SECRET_PATTERNS: dict[str, str] = {
    # Lookbehind avoids matching inside words like "risk-management-framework";
    # sk-ecdsa-/sk-ssh- are FIDO SSH key algorithm names, not API keys.
    "openai_style_key": r"(?<![A-Za-z0-9_-])sk-(?!ecdsa-|ssh-)[A-Za-z0-9_-]{20,}",
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

# Fixture/example content quotes secret-shaped strings by design: test suites,
# skill reference docs, example env files, redaction pattern sources, cached web
# pages, and cron transcripts. Counted separately, never fails the audit.
SECRET_FIXTURE_PATH_SUBSTRINGS = (
    "/tests/",
    "/skills/autonomous-ai-agents/",
    "/cache/web/",
    "/cron/output/",
    "/.claude/worktrees/",
    "/hermes-agent/website/",
    "/hermes-agent/apps/desktop/",
    "/hermes-agent/hermes_cli/web_dist/",
)
SECRET_FIXTURE_FILENAMES = {".env.example", "redact.py", ".gitleaksignore"}

# Legitimate secret stores are supposed to hold real credentials. When their
# permissions are owner-only they count separately and do not fail the audit;
# a loosely-permissioned copy still counts as a live match.
SECRET_STORE_FILENAMES = {".env", "auth.json", "nous_auth.json", "config.yaml"}

# Tailnet exposure (SEC-010, SEC-011). The reviewed list of what `tailscale serve` may
# publish, and the unauthenticated requests each served port must refuse, lives in the
# Hermes home; anything served that it does not list fails the audit.
TAILNET_POLICY_RELATIVE_PATH = Path("security") / "tailnet-exposure.yaml"
TAILSCALE_APP_CLI = "/Applications/Tailscale.app/Contents/MacOS/Tailscale"
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
SECTION_GROUPS = {"tailnet": ("SEC-010", "SEC-011")}

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
            encoding="utf-8",
            errors="replace",
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


def _parse_listeners(lsof_stdout: str) -> list[dict[str, Any]]:
    """One dict per `lsof -nP -iTCP -sTCP:LISTEN` line: process, pid, user, endpoint, port,
    and whether the bind is loopback or all interfaces."""
    services: list[dict[str, Any]] = []
    for line in lsof_stdout.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 9:
            continue
        name, pid, user = parts[0], parts[1], parts[2]
        endpoint = parts[-2] if parts[-1] == "(LISTEN)" else parts[-1]
        bind, _, port = endpoint.rpartition(":")
        loopback = bind in {"127.0.0.1", "[::1]", "localhost"} or bind.endswith(".localhost")
        all_interfaces = bind in {"*", "0.0.0.0", "[::]"}
        services.append({
            "process": name, "pid": pid, "user": user, "endpoint": endpoint,
            "port": int(port) if port.isdigit() else None, "loopback": loopback, "all_interfaces": all_interfaces,
        })
    return services


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
    services = _parse_listeners(result["stdout"])
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
    fixture_counts = {name: 0 for name in compiled}
    store_counts = {name: 0 for name in compiled}
    files: dict[str, set[str]] = {name: set() for name in compiled}
    live_files: dict[str, set[str]] = {name: set() for name in compiled}
    archive_files: dict[str, set[str]] = {name: set() for name in compiled}
    fixture_files: dict[str, set[str]] = {name: set() for name in compiled}
    store_files: dict[str, set[str]] = {name: set() for name in compiled}
    scanned_files = 0
    skipped_large = 0

    def is_fixture_path(path: Path) -> bool:
        if path.name in SECRET_FIXTURE_FILENAMES:
            return True
        posix = path.as_posix()
        return any(marker in posix for marker in SECRET_FIXTURE_PATH_SUBSTRINGS)

    def is_secure_store_path(path: Path) -> bool:
        if path.name not in SECRET_STORE_FILENAMES:
            return False
        try:
            return not (path.stat().st_mode & 0o077)
        except OSError:
            return False

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
                    if is_fixture_path(path):
                        fixture_counts[name] += match_count
                        fixture_files[name].add(display_path)
                    elif is_secure_store_path(path):
                        store_counts[name] += match_count
                        store_files[name].add(display_path)
                    elif is_archive_path(path):
                        archive_counts[name] += match_count
                        archive_files[name].add(display_path)
                    else:
                        live_counts[name] += match_count
                        live_files[name].add(display_path)
    total = sum(counts.values())
    live_total = sum(live_counts.values())
    archive_total = sum(archive_counts.values())
    fixture_total = sum(fixture_counts.values())
    store_total = sum(store_counts.values())
    excluded = f"{fixture_total} fixture/example and {store_total} secured-store match(es) excluded"
    if live_total:
        status = "fail"
        summary = f"{live_total} active secret-like match(es) and {archive_total} historical match(es) found across {scanned_files} scanned file(s) ({excluded})."
    elif archive_total:
        status = "warn"
        summary = f"{archive_total} historical secret-like match(es) found; no active/live matches across {scanned_files} scanned file(s) ({excluded})."
    else:
        status = "pass"
        summary = f"No secret-like matches found across {scanned_files} scanned file(s) ({excluded})."
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
            "fixture_counts": fixture_counts,
            "store_counts": store_counts,
            "files_by_pattern": {name: sorted(paths)[:50] for name, paths in files.items() if paths},
            "live_files_by_pattern": {name: sorted(paths)[:50] for name, paths in live_files.items() if paths},
            "archive_files_by_pattern": {name: sorted(paths)[:50] for name, paths in archive_files.items() if paths},
            "fixture_files_by_pattern": {name: sorted(paths)[:50] for name, paths in fixture_files.items() if paths},
            "store_files_by_pattern": {name: sorted(paths)[:50] for name, paths in store_files.items() if paths},
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
            raw = pid_file.read_text().strip()
            try:
                pid = int(raw)
            except ValueError:
                # Newer gateways write a JSON pid file: {"pid": ..., "kind": ...}.
                pid = int(json.loads(raw)["pid"])
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


def _tailscale_cli() -> str | None:
    found = shutil.which("tailscale")
    if found:
        return found
    return TAILSCALE_APP_CLI if os.access(TAILSCALE_APP_CLI, os.X_OK) else None


def _json_command(cmd: list[str]) -> tuple[dict[str, Any] | None, str]:
    """Parsed JSON object printed by *cmd*, or (None, reason)."""
    result = _run(cmd, timeout=20)
    if not result["ok"]:
        return None, (result["stderr"] or result["stdout"] or "command failed").strip()[:300]
    try:
        data = json.loads(result["stdout"] or "{}")
    except ValueError as exc:
        return None, f"unparsable JSON: {exc}"
    return (data if isinstance(data, dict) else {}), ""


def _tailnet_state() -> tuple[str, dict[str, Any], dict[str, Any], str, str]:
    """(DNS name, `tailscale status --json`, `tailscale serve status --json`, reason, level).
    A non-empty reason means the sections cannot check anything. level "info": nothing can
    be served (no CLI, logged out, stopped). level "warn": the CLI is there but failed, and
    the network extension may still be serving, so the result must not read as clean."""
    cli = _tailscale_cli()
    if cli is None:
        return "", {}, {}, "Tailscale CLI not found; nothing is served on a tailnet.", "info"
    status, err = _json_command([cli, "status", "--json"])
    if status is None:
        return "", {}, {}, f"`tailscale status` failed, so what is served is unknown: {_clip(err)}", "warn"
    if status.get("BackendState") != "Running":
        return "", status, {}, f"Tailscale is {status.get('BackendState') or 'not running'}; nothing is served.", "info"
    serve, err = _json_command([cli, "serve", "status", "--json"])
    if serve is None:
        return "", status, {}, f"`tailscale serve status` failed, so what is served is unknown: {_clip(err)}", "warn"
    dns_name = str((status.get("Self") or {}).get("DNSName") or "").rstrip(".")
    return dns_name, status, serve, "", ""


def _unchecked(section_id: str, title: str, reason: str, level: str) -> AuditSection:
    """A section that could not check; a warn carries the reason as an item so it is seen."""
    return AuditSection(section_id, title, level, reason, {"warnings": [reason]} if level == "warn" else {})


def _clip(text: Any, limit: int = 160) -> str:
    """One line of at most *limit* printable characters, for text that comes from outside
    (headers, error messages) and ends up in reports and prompts."""
    cleaned = "".join(c if c.isprintable() else " " for c in str(text or ""))
    return cleaned if len(cleaned) <= limit else cleaned[: limit - 1] + "…"


def _load_tailnet_policy(hermes_home: Path) -> tuple[dict[str, Any], str]:
    """The reviewed exposure list, or ({}, reason) when the file is missing or unreadable."""
    path = hermes_home / TAILNET_POLICY_RELATIVE_PATH
    if not path.exists():
        return {}, f"{path} not found"
    policy = _parse_yaml(path)
    if not policy:
        return {}, f"{path} is empty or not valid YAML"
    return policy, ""


def _policy_serve(policy: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """policy["serve"] keyed by the port as a string."""
    raw = policy.get("serve")
    return {str(port): entry for port, entry in raw.items() if isinstance(entry, dict)} if isinstance(raw, dict) else {}


def _serve_configs(serve: dict[str, Any]) -> list[dict[str, Any]]:
    """The background serve config plus every foreground `tailscale serve` session."""
    configs = [serve]
    foreground = serve.get("Foreground")
    if isinstance(foreground, dict):
        configs.extend(c for c in foreground.values() if isinstance(c, dict))
    return configs


def _loopback_upstream(url: str) -> tuple[bool, int | None]:
    parsed = urllib.parse.urlparse(url if "://" in url else "http://" + url)
    host = (parsed.hostname or "").lower()
    try:
        port = parsed.port
    except ValueError:
        port = None
    return host in LOOPBACK_HOSTS, port


def check_tailnet_exposure(hermes_home: Path) -> AuditSection:
    """What `tailscale serve` publishes, against the reviewed list in the Hermes home.

    Fails on Funnel (public internet), Tailscale SSH, the web client, advertised routes or
    services, anything served that the list does not name, a served upstream that is not
    a loopback proxy or differs from the list, and any process listening beyond loopback
    that the list's `listeners_allowed` does not name: tailnet peers and the LAN reach it
    without `tailscale serve`. Warns on tailnet devices of other users and on listed ports
    not served. `lsof` runs as this user, so root-owned listeners are not seen.
    """
    title = "Tailnet exposure"
    dns_name, status, serve, reason, level = _tailnet_state()
    if reason:
        return _unchecked("SEC-010", title, reason, level)
    policy, policy_error = _load_tailnet_policy(hermes_home)
    allowed = _policy_serve(policy)
    allowed_tcp = {str(k): str(v) for k, v in (policy.get("tcp_forward") or {}).items()} if isinstance(
        policy.get("tcp_forward"), dict) else {}
    problems: list[str] = []
    warnings: list[str] = []
    if policy_error:
        problems.append(f"no reviewed exposure list ({policy_error}); every served port counts as unreviewed")

    served: list[dict[str, Any]] = []
    for cfg in _serve_configs(serve):
        for host_port, on in (cfg.get("AllowFunnel") or {}).items():
            if on:
                problems.append(f"Funnel is on for {host_port}: it is reachable from the public internet")
        for port, tcp in (cfg.get("TCP") or {}).items():
            forward = tcp.get("TCPForward") if isinstance(tcp, dict) else None
            if forward and allowed_tcp.get(str(port)) != forward:
                problems.append(f"raw TCP forward on :{port} to {forward} is not in the reviewed list")
        if cfg.get("Services"):
            problems.append("Tailscale Services are configured (%s) and not reviewed" % ", ".join(sorted(cfg["Services"])))
        for host_port, body in (cfg.get("Web") or {}).items():
            port = host_port.rsplit(":", 1)[-1]
            for path, handler in ((body or {}).get("Handlers") or {}).items():
                handler = handler if isinstance(handler, dict) else {}
                upstream = str(handler.get("Proxy") or "")
                entry = {"port": port, "path": path, "upstream": upstream or None}
                served.append(entry)
                where = f":{port}{path}"
                if not upstream:
                    kind = "files from " + str(handler["Path"]) if handler.get("Path") else "static text"
                    problems.append(f"{where} serves {kind}, not a loopback proxy")
                    continue
                loopback, upstream_port = _loopback_upstream(upstream)
                entry["upstream_port"] = upstream_port
                if not loopback:
                    problems.append(f"{where} proxies to {upstream}, which is not loopback")
                want = allowed.get(port)
                want_path = str((want or {}).get("path") or "/")
                if not want or want_path != path:
                    problems.append(f"{where} ({upstream}) is not in the reviewed list")
                elif str(want.get("upstream") or "").rstrip("/") != upstream.rstrip("/"):
                    problems.append(f"{where} proxies to {upstream}; the reviewed list says {want.get('upstream')}")

    served_ports = {e["port"] for e in served}
    for port, want in sorted(allowed.items()):
        if port not in served_ports:
            warnings.append(f":{port} ({want.get('name') or want.get('upstream')}) is in the reviewed list but not served")

    upstream_ports = sorted({e["upstream_port"] for e in served if e.get("upstream_port")})
    allowed_listeners = {str(name) for name in policy.get("listeners_allowed") or []}
    listeners_result = _run(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"], timeout=30)
    if listeners_result["stdout"].strip():
        for listener in _parse_listeners(listeners_result["stdout"]):
            if listener["loopback"]:
                continue
            if listener["port"] in upstream_ports:
                problems.append(
                    f"upstream port {listener['port']} also listens on {listener['endpoint']} ({listener['process']}), "
                    "reachable without Tailscale")
            elif listener["process"] not in allowed_listeners:
                problems.append(
                    f"{listener['process']} listens on {listener['endpoint']}: tailnet peers and the LAN reach it "
                    "without tailscale serve, and it is not in listeners_allowed")
    else:
        warnings.append("could not list TCP listeners to confirm nothing else listens beyond loopback")

    prefs, prefs_error = _json_command([_tailscale_cli() or "tailscale", "debug", "prefs"])
    tailscale_ssh = bool((prefs or {}).get("RunSSH"))
    if prefs is None:
        warnings.append(f"could not read Tailscale prefs: {_clip(prefs_error)}")
    else:
        if tailscale_ssh and not policy.get("allow_tailscale_ssh"):
            problems.append("Tailscale SSH is on: tailnet devices the ACL allows can open a shell on this machine")
        if prefs.get("RunWebClient"):
            problems.append("the Tailscale web client is on: tailnet devices can change this machine's Tailscale settings")
        if prefs.get("AdvertiseRoutes"):
            problems.append("this machine advertises routes %s: tailnet devices can reach those networks (or use it as an "
                            "exit node) through it" % ", ".join(map(str, prefs["AdvertiseRoutes"])))
        if prefs.get("AdvertiseServices"):
            problems.append("this machine advertises Tailscale Services %s, which are not reviewed"
                            % ", ".join(map(str, prefs["AdvertiseServices"])))

    self_node = status.get("Self") or {}
    users = status.get("User") or {}
    foreign = sorted(
        str(peer.get("HostName") or peer.get("DNSName") or "?")
        for peer in (status.get("Peer") or {}).values()
        if isinstance(peer, dict) and (peer.get("ShareeNode") or peer.get("UserID") != self_node.get("UserID")))
    if foreign:
        warnings.append(f"{len(foreign)} tailnet device(s) not owned by {users.get(str(self_node.get('UserID')), {}).get('LoginName', 'this user')} "
                        "can reach the served ports unless the tailnet ACL blocks them")
    funnel_allowed = any("funnel" in str(cap) for cap in (self_node.get("CapMap") or {}))
    if funnel_allowed:
        warnings.append("the tailnet policy lets this machine turn Funnel on; remove the funnel node attribute to rule it out")

    status_value = "fail" if problems else "warn" if warnings else "pass"
    # Counts only: summaries land in the scheduled .txt reports, which are kept in git.
    if problems:
        summary = f"{len(problems)} exposure problem(s), {len(warnings)} warning(s) across {len(served)} served handler(s)."
    elif warnings:
        summary = f"{len(served)} served handler(s), all reviewed and loopback-only; {len(warnings)} warning(s)."
    else:
        summary = f"{len(served)} served handler(s), all reviewed and loopback-only; Funnel and Tailscale SSH off."
    data = {
        "dns_name": dns_name,
        "served": served,
        "problems": problems,
        "warnings": warnings,
        "foreign_peers": foreign,
        "tailscale_ssh": tailscale_ssh,
        "funnel_allowed_by_policy": funnel_allowed,
        "policy": str(hermes_home / TAILNET_POLICY_RELATIVE_PATH),
    }
    return AuditSection("SEC-010", title, status_value, summary, data)


def _http_probe(url: str, host_header: str | None = None, method: str = "GET",
                headers: dict[str, str] | None = None, timeout: int = 10) -> tuple[int | None, str, str]:
    """(status, absolute Location, error) for one request without cookies; redirects are not followed."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme == "https":
        conn: http.client.HTTPConnection = http.client.HTTPSConnection(
            parsed.hostname or "", parsed.port or 443, timeout=timeout, context=ssl.create_default_context())
    else:
        conn = http.client.HTTPConnection(parsed.hostname or "", parsed.port or 80, timeout=timeout)
    target = (parsed.path or "/") + (f"?{parsed.query}" if parsed.query else "")
    try:
        conn.request(method, target, body=b"" if method == "POST" else None,
                     headers={**(headers or {}), **({"Host": host_header} if host_header else {})})
        resp = conn.getresponse()
        resp.read(65536)
        location = resp.getheader("Location") or ""
        return resp.status, _clip(urllib.parse.urljoin(url, location), 300) if location else "", ""
    except (OSError, http.client.HTTPException) as exc:
        return None, "", _clip(f"{type(exc).__name__}: {exc}", 200)
    finally:
        conn.close()


def check_tailnet_login_gates(hermes_home: Path) -> AuditSection:
    """Unauthenticated requests through the tailnet URLs, from the reviewed list's `probes`.

    Each probe is `{path, expect}` (served ports) or `{url, host, expect}` (loopback_probes),
    with optional `method`, `headers` and `fail_on`. A probe fails when it gets a 2xx it
    does not expect, or a status in its `fail_on` (e.g. 101 for a WebSocket upgrade): that
    page or API answers without a login. Every served port the list does not name gets a
    `GET /` that fails on any 2xx. Other unexpected answers warn, as does a run in which
    no probe got an answer (the gates went unchecked).
    """
    title = "Tailnet login gates"
    dns_name, _status, serve, reason, level = _tailnet_state()
    if reason:
        return _unchecked("SEC-011", title, reason, level)
    policy, policy_error = _load_tailnet_policy(hermes_home)
    if policy_error:
        failure = f"no reviewed exposure list ({policy_error}), so no login gate was checked"
        return AuditSection("SEC-011", title, "fail", failure, {"failures": [failure], "warnings": [], "probes": []})
    served_ports = {hp.rsplit(":", 1)[-1] for cfg in _serve_configs(serve) for hp in (cfg.get("Web") or {})}
    listed = _policy_serve(policy)

    def fill(value: Any) -> str:
        return str(value).replace("{host}", dns_name)

    jobs: list[tuple[str, str | None, dict[str, Any]]] = []
    warnings: list[str] = []
    for port in sorted(served_ports):
        base = f"https://{dns_name}" + ("" if port == "443" else f":{port}")
        if port not in listed:
            jobs.append((base + "/", None, {"expect": []}))
            continue
        probes = [pr for pr in (listed[port].get("probes") or []) if isinstance(pr, dict) and pr.get("path")]
        if not probes:
            warnings.append(f":{port} is served but the reviewed list has no probes for it")
        jobs.extend((base + str(pr["path"]), None, pr) for pr in probes)
    for pr in policy.get("loopback_probes") or []:
        if isinstance(pr, dict) and pr.get("url"):
            jobs.append((str(pr["url"]), fill(pr.get("host") or "{host}"), pr))

    results: list[dict[str, Any]] = []
    failures: list[str] = []
    for url, host_header, probe in jobs:
        expect = [int(code) for code in (probe.get("expect") or [])]
        fail_on = [int(code) for code in (probe.get("fail_on") or [])]
        method = str(probe.get("method") or "GET").upper()
        headers = {str(k): fill(v) for k, v in (probe.get("headers") or {}).items()}
        code, location, error = _http_probe(url, host_header, method, headers)
        label = (f"{method} " if method != "GET" else "") + url + (f" (Host {host_header})" if host_header else "")
        want_location = fill(probe.get("location") or "")
        note = ""
        if code is None:
            note = f"no answer: {error}"
        elif code not in expect:
            note = f"answered {code}, expected {'/'.join(map(str, expect)) or 'a refusal'}"
        elif want_location and not location.startswith(want_location):
            note = f"redirects to {location or 'nowhere'}, expected {want_location}…"
        if code is not None and ((200 <= code < 300 and code not in expect) or code in fail_on):
            failures.append(f"{label} answers {code} without a login")
        elif note:
            warnings.append(f"{label} {note}")
        results.append({"url": url, "method": method, "host": host_header, "status": code, "expected": expect,
                        "ok": not note})
    if results and all(r["status"] is None for r in results):
        warnings.append("no probe got an answer, so the login gates went unchecked this run")

    status_value = "fail" if failures else "warn" if warnings else "pass"
    if failures:
        summary = f"{len(failures)} of {len(results)} unauthenticated probe(s) got through without a login."
    elif warnings:
        summary = f"{len(results)} probe(s), none answered without a login; {len(warnings)} unexpected answer(s)."
    else:
        summary = f"{len(results)} unauthenticated probe(s) all refused or redirected to a login."
    return AuditSection("SEC-011", title, status_value, summary,
                        {"dns_name": dns_name, "probes": results, "failures": failures, "warnings": warnings})


def _section_checks(home: Path, include_optional: bool) -> list[tuple[str, Callable[[], AuditSection]]]:
    """(section id, check) in report order. Names resolve at call time, so tests can patch them."""
    checks: list[tuple[str, Callable[[], AuditSection]]] = [
        ("SEC-001", check_os_updates),
        ("SEC-002", check_brew_updates),
        ("SEC-003", check_listening_services),
        ("SEC-004", lambda: check_secret_scan(home)),
        ("SEC-005", lambda: check_file_modes(home)),
        ("SEC-006", lambda: check_gateway_status(home)),
        ("SEC-007", lambda: check_terminal_containerization(home)),
    ]
    if include_optional:
        checks += [("SEC-008", check_firewall_sharing), ("SEC-009", lambda: check_git_backup_exposure(home))]
    checks += [("SEC-010", lambda: check_tailnet_exposure(home)), ("SEC-011", lambda: check_tailnet_login_gates(home))]
    return checks


KNOWN_SECTIONS = {f"SEC-{n:03d}" for n in range(1, 12)}


def expand_sections(only: str | None) -> set[str] | None:
    """`--only` value ("tailnet", "SEC-010,SEC-004", ...) as a set of section ids, or None.
    Raises ValueError on an unknown id, so a typo cannot run nothing and report a pass."""
    if not only:
        return None
    ids: set[str] = set()
    for item in (part.strip() for part in only.split(",")):
        if item:
            ids.update(SECTION_GROUPS.get(item.lower(), (item.upper(),)))
    unknown = sorted(ids - KNOWN_SECTIONS)
    if unknown or not ids:
        raise ValueError(f"unknown section(s) for --only: {', '.join(unknown) or only!r}; "
                         f"use ids SEC-001..SEC-011 or: {', '.join(sorted(SECTION_GROUPS))}")
    return ids


def run_local_audit(
    hermes_home: Path | None = None, include_optional: bool = True, only: set[str] | None = None,
) -> dict[str, Any]:
    """Run every section, or only the ids in *only* (optional sections included when named)."""
    home = hermes_home or Path(get_hermes_home())
    checks = _section_checks(home, include_optional or bool(only))
    sections = [check() for section_id, check in checks if only is None or section_id in only]
    overall = "pass"
    for section in sections:
        if STATUS_ORDER[section.status] > STATUS_ORDER[overall]:
            overall = section.status
    return {
        "tool": "hermes security local-audit",
        "local_only": True,
        "hermes_home": str(home),
        "overall_status": overall,
        **({"only": sorted(only)} if only else {}),
        "sections": [section.as_dict() for section in sections],
    }


def _render_human(report: dict[str, Any], details: bool = False) -> str:
    """Text report. *details* adds each section's problem lines (tailnet names, ports); the
    scheduled .txt reports stay at counts and statuses because they are kept in git."""
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
        for key in ("problems", "failures", "warnings") if details else ():
            for item in (data.get(key) or [])[:10]:
                lines.append(f"  - {item}")
        lines.append("")
    return "\n".join(lines).rstrip()


def cmd_local_security_audit(args: argparse.Namespace) -> int:
    home = Path(getattr(args, "hermes_home", None) or get_hermes_home()).expanduser()
    try:
        only = expand_sections(getattr(args, "only", None))
    except ValueError as exc:
        print(f"hermes security local-audit: {exc}", file=sys.stderr)
        return 2
    report = run_local_audit(home, include_optional=not bool(getattr(args, "minimal", False)), only=only)
    if bool(getattr(args, "json", False)):
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(_render_human(report, details=True))
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
    "check_tailnet_exposure",
    "check_tailnet_login_gates",
    "expand_sections",
]
