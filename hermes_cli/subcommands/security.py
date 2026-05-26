"""``hermes security`` subcommand parser.

Extracted verbatim from ``hermes_cli/main.py:main()`` (god-file Phase 2).
Handler injected to avoid importing ``main``.
"""

from __future__ import annotations

from typing import Callable


def build_security_parser(subparsers, *, cmd_security: Callable) -> None:
    """Attach the ``security`` subcommand to ``subparsers``."""
    # =========================================================================
    security_parser = subparsers.add_parser(
        "security",
        help="Supply-chain audit (OSV.dev) for venv, plugins, and MCP servers",
        description=(
            "On-demand vulnerability scan against OSV.dev. Covers the Hermes "
            "venv (installed PyPI dists), Python deps declared by plugins under "
            "~/.hermes/plugins/, and pinned npx/uvx MCP servers in config.yaml. "
            "Does NOT scan globally-installed packages or editor/browser extensions."
        ),
    )
    security_subparsers = security_parser.add_subparsers(
        dest="security_command",
        metavar="<subcommand>",
    )

    audit_parser = security_subparsers.add_parser(
        "audit",
        help="Run a one-shot supply-chain audit",
        description="Query OSV.dev for known vulnerabilities in installed components.",
    )
    audit_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of human-readable text",
    )
    audit_parser.add_argument(
        "--fail-on",
        default="critical",
        choices=["low", "moderate", "high", "critical"],
        help="Exit non-zero when any finding meets this severity (default: critical)",
    )
    audit_parser.add_argument(
        "--skip-venv",
        action="store_true",
        help="Skip scanning the Hermes Python venv",
    )
    audit_parser.add_argument(
        "--skip-plugins",
        action="store_true",
        help="Skip scanning plugin requirements files",
    )
    audit_parser.add_argument(
        "--skip-mcp",
        action="store_true",
        help="Skip scanning pinned MCP servers in config.yaml",
    )
    audit_parser.set_defaults(func=cmd_security)

    local_audit_parser = security_subparsers.add_parser(
        "local-audit",
        help="Run a local-only host/Hermes posture audit",
        description=(
            "Collect local-only security posture checks: cached macOS updates, "
            "Homebrew outdated packages without auto-update, listening services, "
            "Hermes secret-scan counts, sensitive file modes, gateway status, "
            "and terminal backend containerization. Does not contact remote services."
        ),
    )
    local_audit_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of human-readable text",
    )
    local_audit_parser.add_argument(
        "--minimal",
        action="store_true",
        help="Only run required sections; skip optional firewall/sharing and git posture checks",
    )
    local_audit_parser.add_argument(
        "--fail-on-fail",
        action="store_true",
        help="Exit 1 when any required/actionable section reports FAIL",
    )
    local_audit_parser.add_argument(
        "--hermes-home",
        default=None,
        help="Override Hermes home for testing (default: active HERMES_HOME)",
    )
    local_audit_parser.set_defaults(func=cmd_security)

    local_audit_schedule_parser = security_subparsers.add_parser(
        "local-audit-schedule",
        help="Install or run the recurring local security audit job",
        description=(
            "Manage a local-only recurring job for hermes security local-audit. "
            "On macOS, install writes a per-user launchd LaunchAgent that runs "
            "weekly and stores timestamped JSON/TXT reports under "
            "~/.hermes/workspace/security-audits/local-recurring by default."
        ),
    )
    local_audit_schedule_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON for schedule management output",
    )
    schedule_subparsers = local_audit_schedule_parser.add_subparsers(
        dest="schedule_command",
        metavar="{install,run-once,status,uninstall}",
    )

    schedule_install_parser = schedule_subparsers.add_parser(
        "install",
        help="Install and load the weekly macOS launchd job",
    )
    schedule_install_parser.add_argument(
        "--hermes-home",
        default=None,
        help="Hermes home to audit (default: active HERMES_HOME)",
    )
    schedule_install_parser.add_argument(
        "--report-dir",
        default=None,
        help="Directory for timestamped reports",
    )
    schedule_install_parser.add_argument(
        "--plist-path",
        default=None,
        help="Override LaunchAgent plist path for testing",
    )
    schedule_install_parser.add_argument(
        "--keep",
        type=int,
        default=12,
        help="Keep this many recent scheduled runs (default: 12)",
    )
    schedule_install_parser.add_argument(
        "--weekday",
        type=int,
        default=1,
        help="launchd weekday, Sunday=0 (default: 1, Monday)",
    )
    schedule_install_parser.add_argument(
        "--hour",
        type=int,
        default=9,
        help="Local hour 0..23 (default: 9)",
    )
    schedule_install_parser.add_argument(
        "--minute",
        type=int,
        default=0,
        help="Local minute 0..59 (default: 0)",
    )
    schedule_install_parser.add_argument(
        "--minimal",
        action="store_true",
        help="Skip optional audit sections in scheduled runs",
    )
    schedule_install_parser.add_argument(
        "--no-load",
        action="store_true",
        help="Write the plist but do not call launchctl bootstrap",
    )
    schedule_install_parser.set_defaults(func=cmd_security)

    schedule_run_parser = schedule_subparsers.add_parser(
        "run-once",
        help="Run the scheduled audit path once and write timestamped reports",
    )
    schedule_run_parser.add_argument(
        "--hermes-home",
        default=None,
        help="Hermes home to audit (default: active HERMES_HOME)",
    )
    schedule_run_parser.add_argument(
        "--report-dir",
        default=None,
        help="Directory for timestamped reports",
    )
    schedule_run_parser.add_argument(
        "--keep",
        type=int,
        default=12,
        help="Keep this many recent scheduled runs (default: 12)",
    )
    schedule_run_parser.add_argument(
        "--minimal",
        action="store_true",
        help="Skip optional audit sections",
    )
    schedule_run_parser.set_defaults(func=cmd_security)

    schedule_status_parser = schedule_subparsers.add_parser(
        "status",
        help="Show local audit schedule status",
    )
    schedule_status_parser.add_argument(
        "--report-dir",
        default=None,
        help="Directory containing timestamped reports",
    )
    schedule_status_parser.add_argument(
        "--plist-path",
        default=None,
        help="Override LaunchAgent plist path",
    )
    schedule_status_parser.set_defaults(func=cmd_security)

    schedule_uninstall_parser = schedule_subparsers.add_parser(
        "uninstall",
        help="Unload and remove the LaunchAgent plist",
    )
    schedule_uninstall_parser.add_argument(
        "--plist-path",
        default=None,
        help="Override LaunchAgent plist path",
    )
    schedule_uninstall_parser.set_defaults(func=cmd_security)

    local_audit_schedule_parser.set_defaults(func=cmd_security)

    security_parser.set_defaults(func=cmd_security)
