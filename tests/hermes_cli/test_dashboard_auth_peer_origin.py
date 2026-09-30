"""The session token is withheld from loopback requests that a container or VM proxy relays."""

from __future__ import annotations

import socket
import subprocess
from types import SimpleNamespace

from hermes_cli.dashboard_auth import peer_origin as po


def _lsof(stdout: str):
    return lambda *a, **k: subprocess.CompletedProcess(a, 0, stdout=stdout, stderr="")


LSOF_DOCKER = (
    "p89135\ncom.docker.backend\nn127.0.0.1:64291->127.0.0.1:63544\n"
    "p79154\nchermes\nn127.0.0.1:63544->127.0.0.1:64291\n"
).replace("\ncom.docker", "\nccom.docker")


def test_docker_backend_peer_is_a_proxy(monkeypatch):
    monkeypatch.setattr(po.shutil, "which", lambda name: "/usr/sbin/lsof")
    monkeypatch.setattr(po.subprocess, "run", _lsof(LSOF_DOCKER))
    assert po.peer_command("127.0.0.1", 64291) == ("com.docker.backend", "")
    assert po.is_container_proxy("127.0.0.1", 64291)


def test_local_process_peer_is_not_a_proxy(monkeypatch):
    stdout = "p4242\ncHermes Helper\nn127.0.0.1:50000->127.0.0.1:63544\n"
    monkeypatch.setattr(po.shutil, "which", lambda name: "/usr/sbin/lsof")
    monkeypatch.setattr(po.subprocess, "run", _lsof(stdout))
    assert not po.is_container_proxy("127.0.0.1", 50000)


def test_unknown_owner_fails_closed(monkeypatch):
    monkeypatch.setattr(po.shutil, "which", lambda name: "/usr/sbin/lsof")
    monkeypatch.setattr(po.subprocess, "run", _lsof(""))
    assert po.is_container_proxy("127.0.0.1", 50001)


def test_no_lsof_or_non_loopback_peer_does_not_apply(monkeypatch):
    monkeypatch.setattr(po.shutil, "which", lambda name: None)
    monkeypatch.setattr(po.sys, "platform", "linux")
    assert not po.is_container_proxy("127.0.0.1", 50002)
    assert not po.is_container_proxy("testclient", 50000)
    assert not po.is_container_proxy("192.168.1.5", 50000)
    assert not po.request_is_container_proxied(SimpleNamespace(client=None))


def test_ipv6_loopback_endpoint_format(monkeypatch):
    stdout = "p1\nccom.docker.backend\nn[::1]:50003->[::1]:63544\n"
    monkeypatch.setattr(po.shutil, "which", lambda name: "/usr/sbin/lsof")
    monkeypatch.setattr(po.subprocess, "run", _lsof(stdout))
    assert po.is_container_proxy("::1", 50003)


def test_real_loopback_connection_resolves_to_this_process():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    cli = socket.create_connection(srv.getsockname())
    conn, (host, port) = srv.accept()
    try:
        if po.shutil.which("lsof") is None:
            return
        command, error = po.peer_command(host, port)
        assert command, error
        assert not po.is_container_proxy(host, port)
    finally:
        cli.close()
        conn.close()
        srv.close()


def test_ipv4_mapped_loopback_is_checked(monkeypatch):
    stdout = "p1\nccom.docker.backend\nn[::ffff:127.0.0.1]:50004->[::ffff:127.0.0.1]:63544\n"
    monkeypatch.setattr(po.shutil, "which", lambda name: "/usr/sbin/lsof")
    monkeypatch.setattr(po.subprocess, "run", _lsof(stdout))
    assert po.is_container_proxy("::ffff:127.0.0.1", 50004)


# What Node's fetch actually sends (measured): the Electron main process must pass.
NODE_FETCH = {"accept": "*/*", "accept-language": "*", "sec-fetch-mode": "cors", "user-agent": "node"}


def test_browser_markers():
    req = lambda **h: SimpleNamespace(headers=h)
    assert po.request_is_from_a_browser(req(**{"sec-fetch-site": "none", "sec-fetch-dest": "document"}))
    assert po.request_is_from_a_browser(req(origin="http://127.0.0.1:8088"))
    assert not po.request_is_from_a_browser(req(**NODE_FETCH))
    assert not po.request_is_from_a_browser(req())
    assert po.request_is_cross_origin_read(req(origin="http://127.0.0.1:8088"))
    assert po.request_is_cross_origin_read(req(**{"sec-fetch-mode": "cors", "sec-fetch-site": "same-site"}))
    assert not po.request_is_cross_origin_read(req(**{"sec-fetch-mode": "cors", "sec-fetch-site": "same-origin"}))
    assert not po.request_is_cross_origin_read(req(**{"sec-fetch-mode": "navigate", "sec-fetch-site": "cross-site"}))
    assert not po.request_is_cross_origin_read(req(**NODE_FETCH))
    assert not po.request_is_cross_origin_read(req())
