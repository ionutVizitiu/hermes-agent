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
    monkeypatch.setattr(lsa, "check_tailnet_exposure", lambda home: sec("SEC-010"))
    monkeypatch.setattr(lsa, "check_tailnet_login_gates", lambda home: sec("SEC-011"))

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
        "SEC-010",
        "SEC-011",
    ]


def test_cmd_json_exit_code_only_fails_with_flag(monkeypatch, tmp_path: Path, capsys):
    report = {
        "tool": "hermes security local-audit",
        "local_only": True,
        "hermes_home": str(tmp_path),
        "overall_status": "fail",
        "sections": [],
    }
    monkeypatch.setattr(lsa, "run_local_audit", lambda home, include_optional=True, only=None: report)

    args = argparse.Namespace(json=True, minimal=False, fail_on_fail=False, hermes_home=str(tmp_path))
    assert lsa.cmd_local_security_audit(args) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["overall_status"] == "fail"

    args.fail_on_fail = True
    assert lsa.cmd_local_security_audit(args) == 1


# --- tailnet exposure (SEC-010, SEC-011) --------------------------------------------------

HOST = "mac.tail0.ts.net"
POLICY = """
serve:
  443: {name: bookmarks, upstream: "http://127.0.0.1:3000", probes: [{path: /api/v1/x, expect: [401]}]}
  8444:
    name: dashboard
    upstream: http://127.0.0.1:9119
    probes:
      - {path: /kanban, expect: [302], location: "https://{host}:8444/login?"}
loopback_probes:
  - {url: "http://127.0.0.1:8770/", host: "{host}:8443", expect: [421]}
"""


def _serve(*entries: tuple[str, str]) -> dict:
    return {"TCP": {port: {"HTTPS": True} for port, _ in entries},
            "Web": {f"{HOST}:{port}": {"Handlers": {"/": {"Proxy": up}}} for port, up in entries}}


def _status(peers: dict | None = None) -> dict:
    return {"BackendState": "Running", "Self": {"DNSName": HOST + ".", "UserID": 1, "CapMap": {}},
            "User": {"1": {"LoginName": "owner@example.com"}}, "Peer": peers or {}}


LSOF_HEADER = "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n"


def _lsof(*endpoints: str) -> str:
    return LSOF_HEADER + "".join(f"proc 1 me 4u IPv4 0x0 0t0 TCP {e} (LISTEN)\n" for e in endpoints)


def _patch_tailnet(monkeypatch, tmp_path: Path, serve: dict, *, status: dict | None = None,
                   lsof: str = "", prefs: dict | None = None, policy: str | None = POLICY) -> None:
    if policy is not None:
        (tmp_path / "security").mkdir(exist_ok=True)
        (tmp_path / "security" / "tailnet-exposure.yaml").write_text(policy, encoding="utf-8")
    monkeypatch.setattr(lsa, "_tailnet_state", lambda: (HOST, status or _status(), serve, ""))
    monkeypatch.setattr(lsa, "_tailscale_cli", lambda: "tailscale")
    monkeypatch.setattr(lsa, "_json_command", lambda cmd: (prefs if prefs is not None else {"RunSSH": False}, ""))
    monkeypatch.setattr(lsa, "_run", lambda cmd, timeout=20, env=None: {
        "ok": True, "returncode": 0, "stdout": lsof, "stderr": "", "missing": False})


def test_expand_sections_groups_and_ids():
    assert lsa.expand_sections(None) is None
    assert lsa.expand_sections("tailnet") == {"SEC-010", "SEC-011"}
    assert lsa.expand_sections("sec-004, tailnet") == {"SEC-004", "SEC-010", "SEC-011"}


def test_run_local_audit_only_runs_the_named_sections(monkeypatch, tmp_path: Path):
    def boom(*_a):
        raise AssertionError("section should not run")

    for name in ("check_os_updates", "check_brew_updates", "check_listening_services", "check_secret_scan",
                 "check_file_modes", "check_gateway_status", "check_terminal_containerization",
                 "check_firewall_sharing", "check_git_backup_exposure", "check_tailnet_login_gates"):
        monkeypatch.setattr(lsa, name, boom)
    monkeypatch.setattr(lsa, "check_tailnet_exposure", lambda home: lsa.AuditSection("SEC-010", "t", "fail", "s"))

    report = lsa.run_local_audit(tmp_path, include_optional=False, only={"SEC-010"})

    assert [section["id"] for section in report["sections"]] == ["SEC-010"]
    assert report["only"] == ["SEC-010"]
    assert report["overall_status"] == "fail"


def test_tailnet_exposure_passes_for_reviewed_loopback_services(monkeypatch, tmp_path: Path):
    _patch_tailnet(monkeypatch, tmp_path, _serve(("443", "http://127.0.0.1:3000"), ("8444", "http://127.0.0.1:9119")),
                   lsof=_lsof("127.0.0.1:3000", "127.0.0.1:9119", "*:5000"))

    section = lsa.check_tailnet_exposure(tmp_path)

    assert section.status == "pass", section.data
    assert section.data["problems"] == []


def test_tailnet_exposure_fails_on_funnel_unreviewed_and_non_loopback(monkeypatch, tmp_path: Path):
    serve = _serve(("443", "http://127.0.0.1:3000"), ("8444", "http://127.0.0.1:9119"), ("10000", "http://10.0.0.5:80"))
    serve["AllowFunnel"] = {f"{HOST}:443": True}
    _patch_tailnet(monkeypatch, tmp_path, serve, lsof=_lsof("*:9119", "127.0.0.1:3000"), prefs={"RunSSH": True})

    section = lsa.check_tailnet_exposure(tmp_path)
    problems = "\n".join(section.data["problems"])

    assert section.status == "fail"
    assert "Funnel is on" in problems
    assert ":10000/ (http://10.0.0.5:80) is not in the reviewed list" in problems
    assert "not loopback" in problems
    assert "upstream port 9119 also listens on *:9119" in problems
    assert "Tailscale SSH is on" in problems


def test_tailnet_exposure_fails_when_upstream_differs_or_policy_missing(monkeypatch, tmp_path: Path):
    _patch_tailnet(monkeypatch, tmp_path, _serve(("8444", "http://127.0.0.1:8770")), policy=None)
    assert "no reviewed exposure list" in "\n".join(lsa.check_tailnet_exposure(tmp_path).data["problems"])

    _patch_tailnet(monkeypatch, tmp_path, _serve(("8444", "http://127.0.0.1:8770")))
    section = lsa.check_tailnet_exposure(tmp_path)
    assert section.status == "fail"
    assert any("the reviewed list says http://127.0.0.1:9119" in p for p in section.data["problems"])
    assert any(":443 (bookmarks) is in the reviewed list but not served" in w for w in section.data["warnings"])


def test_tailnet_exposure_warns_on_other_users_devices(monkeypatch, tmp_path: Path):
    peers = {"a": {"HostName": "phone", "UserID": 1}, "b": {"HostName": "guest-laptop", "UserID": 2}}
    _patch_tailnet(monkeypatch, tmp_path, _serve(("443", "http://127.0.0.1:3000"), ("8444", "http://127.0.0.1:9119")),
                   status=_status(peers), lsof=_lsof("127.0.0.1:3000", "127.0.0.1:9119"))

    section = lsa.check_tailnet_exposure(tmp_path)

    assert section.status == "warn"
    assert section.data["foreign_peers"] == ["guest-laptop"]


def test_tailnet_exposure_is_info_without_tailscale(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(lsa, "_tailnet_state", lambda: ("", {}, {}, "Tailscale CLI not found; nothing is served on a tailnet."))
    assert lsa.check_tailnet_exposure(tmp_path).status == "info"
    assert lsa.check_tailnet_login_gates(tmp_path).status == "info"


def test_login_gates_fail_on_unexpected_2xx_and_pass_redirects(monkeypatch, tmp_path: Path):
    _patch_tailnet(monkeypatch, tmp_path, _serve(("443", "http://127.0.0.1:3000"), ("8444", "http://127.0.0.1:9119")))
    seen = []

    def probe(url, host_header=None, timeout=10):
        seen.append((url, host_header))
        if url.endswith("/kanban"):
            return 302, f"https://{HOST}:8444/login?next=%2Fkanban", ""
        if url.startswith("http://127.0.0.1:8770"):
            return 421, "", ""
        return 200, "", ""  # the bookmarks API answers without a login

    monkeypatch.setattr(lsa, "_http_probe", probe)

    section = lsa.check_tailnet_login_gates(tmp_path)

    assert section.status == "fail"
    assert section.data["failures"] == [f"https://{HOST}/api/v1/x answers 200 without a login"]
    assert (f"https://{HOST}:8444/kanban", None) in seen
    assert ("http://127.0.0.1:8770/", f"{HOST}:8443") in seen


def test_login_gates_warn_when_a_service_does_not_answer(monkeypatch, tmp_path: Path):
    _patch_tailnet(monkeypatch, tmp_path, _serve(("8444", "http://127.0.0.1:9119")))
    monkeypatch.setattr(lsa, "_http_probe", lambda url, host_header=None, timeout=10: (None, "", "ConnectionRefusedError"))

    section = lsa.check_tailnet_login_gates(tmp_path)

    assert section.status == "warn"
    assert section.data["failures"] == []
    assert any("no answer" in w for w in section.data["warnings"])


def test_http_probe_resolves_relative_location(monkeypatch):
    class Resp:
        status = 302

        def read(self, n):
            return b""

        def getheader(self, name):
            return "/login?next=%2Fkanban" if name == "Location" else None

    class Conn:
        def __init__(self, *a, **k):
            self.sent = None

        def request(self, method, target, headers=None):
            assert (method, target, headers) == ("GET", "/kanban", {})

        def getresponse(self):
            return Resp()

        def close(self):
            pass

    monkeypatch.setattr(lsa.http.client, "HTTPSConnection", Conn)
    assert lsa._http_probe(f"https://{HOST}:8444/kanban") == (302, f"https://{HOST}:8444/login?next=%2Fkanban", "")


def test_text_report_keeps_problem_lines_out_unless_asked():
    report = {"overall_status": "fail", "hermes_home": "/h", "sections": [{
        "id": "SEC-010", "title": "Tailnet exposure", "status": "fail", "summary": "1 problem",
        "data": {"problems": [f"Funnel is on for {HOST}:443"]}, "errors": []}]}
    assert HOST not in lsa._render_human(report)
    assert f"- Funnel is on for {HOST}:443" in lsa._render_human(report, details=True)
