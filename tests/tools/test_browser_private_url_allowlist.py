"""``browser.private_url_allowlist``: exact origins that skip the browser's private-address check
on non-local backends (cloud provider, or a containerized terminal whose browser runs on the host)."""

import json

import pytest

from tools import browser_tool
from tools import browser_tool_cloud as bt_cloud
from tools import browser_tool_session as bt_session


@pytest.fixture(autouse=True)
def _reset_cache():
    browser_tool._private_url_allowlist_resolved = False
    browser_tool._cached_private_url_allowlist = ()
    yield
    browser_tool._private_url_allowlist_resolved = False
    browser_tool._cached_private_url_allowlist = ()


def _config(monkeypatch, allowlist):
    monkeypatch.setattr("hermes_cli.config.read_raw_config",
                        lambda: {"browser": {"private_url_allowlist": allowlist}})


class TestParse:
    def test_accepts_host_host_port_and_origin(self):
        assert bt_cloud._parse_private_url_allowlist(
            ["127.0.0.1:8088", "Shop.Localhost", "https://[::1]:8443/", "http://dev.test."]
        ) == (
            (None, "127.0.0.1", 8088),
            (None, "shop.localhost", None),
            ("https", "::1", 8443),
            ("http", "dev.test", None),
        )

    def test_single_string_is_one_entry(self):
        assert bt_cloud._parse_private_url_allowlist("127.0.0.1:8088") == ((None, "127.0.0.1", 8088),)

    @pytest.mark.parametrize("entry", [
        "*.localhost", "127.0.0.1:8088/wp-admin", "http://127.0.0.1/?x=1", "user@127.0.0.1",
        "ftp://127.0.0.1", "127.0.0.1:notaport", "", "   ",
    ])
    def test_rejects_anything_broader_or_malformed(self, entry):
        assert bt_cloud._parse_private_url_allowlist([entry]) == ()

    @pytest.mark.parametrize("raw", [None, 8088, {"host": "127.0.0.1"}])
    def test_non_list_values_mean_empty(self, raw):
        assert bt_cloud._parse_private_url_allowlist(raw) == ()


class TestMatch:
    @pytest.mark.parametrize("url", [
        "http://127.0.0.1:8088/politica-de-confidentialitate/",
        "http://127.0.0.1:8088",
        "https://127.0.0.1:8088/x",  # no scheme in the entry: either scheme matches
    ])
    def test_listed_origin_matches(self, monkeypatch, url):
        _config(monkeypatch, ["127.0.0.1:8088"])
        assert bt_cloud._private_url_allowlisted(url) is True

    @pytest.mark.parametrize("url", [
        "http://127.0.0.1:8089/",   # other port
        "http://127.0.0.1/",        # default port 80
        "http://localhost:8088/",   # same machine, different name
        "http://127.0.0.2:8088/",
        "file:///etc/passwd",
        "not a url",
    ])
    def test_everything_else_does_not(self, monkeypatch, url):
        _config(monkeypatch, ["127.0.0.1:8088"])
        assert bt_cloud._private_url_allowlisted(url) is False

    def test_scheme_and_default_port_from_origin_entry(self, monkeypatch):
        _config(monkeypatch, ["https://shop.localhost"])
        assert bt_cloud._private_url_allowlisted("https://shop.localhost/cart") is True
        assert bt_cloud._private_url_allowlisted("http://shop.localhost/cart") is False

    def test_host_without_port_matches_any_port(self, monkeypatch):
        _config(monkeypatch, ["shop.localhost"])
        assert bt_cloud._private_url_allowlisted("http://shop.localhost:3000/") is True

    def test_empty_by_default(self, monkeypatch):
        monkeypatch.setattr("hermes_cli.config.read_raw_config", lambda: {"browser": {}})
        assert bt_cloud._private_url_allowlisted("http://127.0.0.1:8088/") is False


class TestBrowserVerdict:
    def test_allowlisted_private_url_is_safe(self, monkeypatch):
        _config(monkeypatch, ["127.0.0.1:8088"])
        assert browser_tool._is_safe_url("http://127.0.0.1:8088/") is True
        assert browser_tool._is_safe_url("http://127.0.0.1:9177/") is False

    def test_metadata_floor_beats_allowlist(self, monkeypatch):
        _config(monkeypatch, ["169.254.169.254", "metadata.google.internal"])
        assert browser_tool._is_safe_url("http://169.254.169.254/latest/meta-data/") is False
        assert browser_tool._is_safe_url("http://metadata.google.internal/") is False


class TestNavigate:
    @pytest.fixture()
    def _cloud_mode(self, monkeypatch):
        monkeypatch.setattr(browser_tool, "_is_camofox_mode", lambda: False)
        monkeypatch.setattr(browser_tool, "check_website_access", lambda url: None)
        monkeypatch.setattr(bt_cloud, "_is_local_backend", lambda: False)
        monkeypatch.setattr(bt_cloud, "_allow_private_urls", lambda: False)
        monkeypatch.setattr(bt_session, "_get_session_info", lambda task_id: {
            "session_name": f"s_{task_id}", "bb_session_id": None, "cdp_url": None,
            "features": {"local": True}, "_first_nav": False})
        final = {"url": None}
        monkeypatch.setattr(bt_session, "_run_browser_command", lambda *a, **kw: {
            "success": True, "data": {"title": "OK", "url": final["url"] or a[2][0]}})
        return final

    def test_allowlisted_url_navigates(self, monkeypatch, _cloud_mode):
        _config(monkeypatch, ["127.0.0.1:8088"])
        result = json.loads(browser_tool.browser_navigate("http://127.0.0.1:8088/"))
        assert result["success"] is True

    def test_unlisted_private_url_still_blocked(self, monkeypatch, _cloud_mode):
        _config(monkeypatch, ["127.0.0.1:8088"])
        result = json.loads(browser_tool.browser_navigate("http://127.0.0.1:9177/"))
        assert result["success"] is False
        assert "private or internal address" in result["error"]

    def test_redirect_off_the_allowlist_is_blocked(self, monkeypatch, _cloud_mode):
        _config(monkeypatch, ["127.0.0.1:8088"])
        _cloud_mode["url"] = "http://192.168.1.1/admin"
        result = json.loads(browser_tool.browser_navigate("http://127.0.0.1:8088/"))
        assert result["success"] is False
        assert "private/internal address" in result["error"]

    def test_browser_exec_url_scan_honors_allowlist(self, monkeypatch, _cloud_mode):
        from tools import browser_use_cli
        _config(monkeypatch, ["127.0.0.1:8088"])
        assert browser_use_cli._blocked_url_in_code("new_tab('http://127.0.0.1:8088/x')") is None
        assert "private or internal" in browser_use_cli._blocked_url_in_code("new_tab('http://10.0.0.5/')")
