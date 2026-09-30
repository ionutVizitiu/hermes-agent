"""Is a loopback request from this machine, or proxied in from a container or VM?

Docker Desktop (and the other VM-based container hosts) forward a container's connection
to ``host.docker.internal:<port>`` through a host process that dials ``127.0.0.1:<port>``.
The request then looks local: peer 127.0.0.1, and any Host header the container likes.
What it cannot forge is which process owns the other end of the socket, so the pages that
hand out the session token (the headless Desktop handshake at ``/`` and an ungated
dashboard's index.html) ask ``lsof`` for that owner and withhold the token from these
proxies. Everything else about the connection is unchanged.
"""
from __future__ import annotations

import ipaddress
import logging
import shutil
import subprocess
import sys
from typing import Optional

_log = logging.getLogger(__name__)

# Host-side processes that relay container or VM traffic onto the Mac's loopback, matched
# as command-name prefixes (``lsof +c 0`` prints full names).
PROXY_COMMAND_PREFIXES = (
    "com.docker.",  # Docker Desktop: com.docker.backend, com.docker.vpnkit
    "vpnkit",
    "docker-proxy",
    "OrbStack",
    "limactl",  # Lima, Colima, Rancher Desktop
    "gvproxy",  # Podman machine
    "qemu-system",
    "vmnet-natd",  # VMware Fusion NAT
    "prl_naptd",  # Parallels NAT
    "com.apple.Virtualization",
)
_LSOF_TIMEOUT_SECONDS = 2.0
_warned_no_lsof = False


def _is_loopback(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        return False
    mapped = getattr(ip, "ipv4_mapped", None)  # ::ffff:127.0.0.1 on a dual-stack bind
    return (mapped or ip).is_loopback


def _lsof_endpoint(host: str, port: int) -> str:
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def peer_command(client_host: str, client_port: int) -> tuple[Optional[str], str]:
    """(command owning the client end of a loopback TCP connection, error)."""
    lsof = shutil.which("lsof") or ("/usr/sbin/lsof" if sys.platform == "darwin" else None)
    if not lsof:
        return None, "lsof not found"
    endpoint = _lsof_endpoint(client_host, client_port)
    try:
        proc = subprocess.run(
            [lsof, "+c", "0", "-nP", "-a", f"-iTCP@{endpoint}", "-sTCP:ESTABLISHED", "-Fpcn"],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=_LSOF_TIMEOUT_SECONDS, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, f"lsof failed: {exc}"
    command: Optional[str] = None
    for line in proc.stdout.splitlines():
        field, value = line[:1], line[1:]
        if field == "p":
            command = None
        elif field == "c":
            command = value
        elif field == "n" and value.startswith(f"{endpoint}->"):
            return command, ""
    return None, "no process owns the client end (the connection already closed)"


def is_container_proxy(client_host: Optional[str], client_port: Optional[int]) -> bool:
    """True when the peer of a loopback request is a container or VM network proxy, or when
    that cannot be ruled out although it can be checked (fail closed). Non-loopback peers and
    platforms without lsof return False: the check does not apply there."""
    global _warned_no_lsof
    if not client_host or not client_port or not _is_loopback(client_host):
        return False
    command, error = peer_command(client_host, int(client_port))
    if command is None:
        if error == "lsof not found":
            if not _warned_no_lsof:
                _warned_no_lsof = True
                _log.warning("lsof not found: cannot tell container-proxied loopback requests from local ones")
            return False
        _log.warning("withholding the session token: %s", error)
        return True
    if command.startswith(PROXY_COMMAND_PREFIXES):
        _log.warning("withholding the session token from %s: it relays container or VM traffic", command)
        return True
    return False


def request_is_container_proxied(request) -> bool:
    client = getattr(request, "client", None)
    return is_container_proxy(getattr(client, "host", None), getattr(client, "port", None))


def request_is_cross_origin_read(request) -> bool:
    """True for a browser fetch/XHR, which another page could read: an Origin header, or a
    Sec-Fetch-Mode other than a navigation. The CORS policy lets any localhost origin read
    responses, so a page served on another loopback port must not get the token that way.
    Top-level navigations (the dashboard opened in a browser) and non-browser clients (the
    Electron main process, curl) pass."""
    headers = getattr(request, "headers", {}) or {}
    mode = headers.get("sec-fetch-mode")
    return bool(headers.get("origin")) or bool(mode and mode != "navigate")


def request_is_from_a_browser(request) -> bool:
    """True when any browser marker is present. The headless token page serves only the
    Electron main process, whose fetch sends none of them."""
    headers = getattr(request, "headers", {}) or {}
    return any(headers.get(h) for h in ("origin", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-dest"))
