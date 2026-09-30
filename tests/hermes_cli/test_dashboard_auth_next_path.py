"""Post-login ``next`` targets must stay on the dashboard's origin."""

from __future__ import annotations

import pytest

from hermes_cli.dashboard_auth.request_utils import is_safe_next_path


@pytest.mark.parametrize("path", ["/", "/kanban", "/hub?to=/panel/", "/sessions?id=abc%20def"])
def test_same_origin_paths_pass(path):
    assert is_safe_next_path(path)


@pytest.mark.parametrize("path", [
    "//evil.example/",
    "/\\evil.example/",
    "/\t/evil.example/",
    "/\n/evil.example/",
    "/ /evil.example/",
    "/\x7f/evil.example/",
    "https://evil.example/",
    "evil.example",
    "/login",
    "/api/config",
])
def test_paths_that_leave_the_origin_or_loop_fail(path):
    assert not is_safe_next_path(path)
