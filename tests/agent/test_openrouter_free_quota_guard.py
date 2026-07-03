"""Tests for the OpenRouter free-model daily quota breaker.

Covers agent/openrouter_free_quota_guard.py (cross-session state) and the
error-classifier handling of ``free-models-per-day`` 429s (no credential
rotation — a daily model-tier quota must not poison the pool for paid
models on the same key).
"""

import json
import os
import time

import pytest


@pytest.fixture
def quota_guard_env(tmp_path, monkeypatch):
    """Isolate breaker state to a temp directory."""
    hermes_home = str(tmp_path / ".hermes")
    os.makedirs(hermes_home, exist_ok=True)
    monkeypatch.setenv("HERMES_HOME", hermes_home)
    return hermes_home


class MockAPIError(Exception):
    def __init__(self, message, status_code=None, body=None):
        super().__init__(message)
        self.status_code = status_code
        self.body = body


# The exact body shape OpenRouter returns for the daily free-model cap.
FREE_DAILY_BODY = {
    "error": {
        "message": "Rate limit exceeded: free-models-per-day-high-balance. ",
        "code": 429,
        "metadata": {
            "headers": {
                "X-RateLimit-Limit": "1000",
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": "1783123200000",
            },
            "provider_name": None,
        },
    }
}


class TestIsFreeModel:
    def test_free_suffix(self):
        from agent.openrouter_free_quota_guard import is_free_model

        assert is_free_model("nvidia/nemotron-3-ultra-550b-a55b:free")
        assert is_free_model("google/gemma-4-31b-it:FREE")

    def test_paid_and_junk(self):
        from agent.openrouter_free_quota_guard import is_free_model

        assert not is_free_model("deepseek/deepseek-v4-flash")
        assert not is_free_model(None)
        assert not is_free_model(123)


class TestRecordAndRemaining:
    def test_roundtrip_with_context_reset_ms(self, quota_guard_env):
        from agent.openrouter_free_quota_guard import (
            _state_path,
            clear_free_quota,
            free_quota_remaining,
            record_free_quota_exhausted,
        )

        reset_ms = (time.time() + 7200) * 1000.0
        record_free_quota_exhausted(
            error_context={"openrouter_free_daily_reset_ms": reset_ms},
        )

        assert os.path.exists(_state_path())
        remaining = free_quota_remaining()
        assert remaining is not None
        assert remaining == pytest.approx(7200, abs=10)

        clear_free_quota()
        assert free_quota_remaining() is None
        assert not os.path.exists(_state_path())

    def test_reset_from_http_headers(self, quota_guard_env):
        from agent.openrouter_free_quota_guard import (
            free_quota_remaining,
            record_free_quota_exhausted,
        )

        reset_ms = (time.time() + 3600) * 1000.0
        record_free_quota_exhausted(headers={"X-RateLimit-Reset": str(reset_ms)})
        assert free_quota_remaining() == pytest.approx(3600, abs=10)

    def test_default_is_next_utc_midnight(self, quota_guard_env):
        from agent.openrouter_free_quota_guard import (
            _state_path,
            record_free_quota_exhausted,
        )

        record_free_quota_exhausted()
        with open(_state_path()) as f:
            state = json.load(f)
        expected = 86400.0 - (state["recorded_at"] % 86400.0)
        assert state["reset_seconds"] == pytest.approx(expected, abs=5)
        assert 60.0 <= state["reset_seconds"] <= 86400.0 + 60.0

    def test_garbage_reset_is_capped(self, quota_guard_env):
        from agent.openrouter_free_quota_guard import (
            _state_path,
            record_free_quota_exhausted,
        )

        # A reset a year out must be clamped to ~26h.
        reset_ms = (time.time() + 365 * 86400) * 1000.0
        record_free_quota_exhausted(
            error_context={"openrouter_free_daily_reset_ms": reset_ms},
        )
        with open(_state_path()) as f:
            state = json.load(f)
        assert state["reset_seconds"] <= 26 * 3600 + 5

    def test_past_reset_falls_back_to_midnight(self, quota_guard_env):
        from agent.openrouter_free_quota_guard import (
            free_quota_remaining,
            record_free_quota_exhausted,
        )

        reset_ms = (time.time() - 600) * 1000.0
        record_free_quota_exhausted(
            error_context={"openrouter_free_daily_reset_ms": reset_ms},
        )
        remaining = free_quota_remaining()
        assert remaining is not None and remaining >= 55

    def test_expired_state_reports_healthy_and_cleans_up(self, quota_guard_env):
        from agent.openrouter_free_quota_guard import (
            _state_path,
            free_quota_remaining,
        )

        path = _state_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump({"reset_at": time.time() - 10, "recorded_at": time.time() - 100}, f)
        assert free_quota_remaining() is None
        assert not os.path.exists(path)

    def test_missing_state_is_healthy(self, quota_guard_env):
        from agent.openrouter_free_quota_guard import free_quota_remaining

        assert free_quota_remaining() is None

    def test_state_is_shared_across_profiles(self, tmp_path, monkeypatch):
        """A profile-scoped HERMES_HOME must write to the ROOT home —
        the daily quota is account-wide, so one profile's breaker has to
        be visible to every other profile."""
        root = tmp_path / "hermes-root"
        profile = root / "profiles" / "worker"
        os.makedirs(profile, exist_ok=True)
        monkeypatch.setenv("HERMES_HOME", str(profile))

        from agent.openrouter_free_quota_guard import _state_path

        assert _state_path() == os.path.join(
            str(root), "rate_limits", "openrouter_free.json"
        )


class TestClassifierFreeDailyQuota:
    def _classify(self, provider="openrouter"):
        from agent.error_classifier import classify_api_error

        err = MockAPIError(
            "HTTP 429: Rate limit exceeded: free-models-per-day-high-balance.",
            status_code=429,
            body=FREE_DAILY_BODY,
        )
        return classify_api_error(
            err,
            provider=provider,
            model="nvidia/nemotron-3-ultra-550b-a55b:free",
        )

    def test_no_credential_rotation(self):
        from agent.error_classifier import FailoverReason

        classified = self._classify()
        # Rotating keys on the same account can't recover a daily
        # model-tier quota, and marking the key exhausted poisons the
        # pool for paid models — must route to fallback instead.
        assert classified.reason == FailoverReason.upstream_rate_limit
        assert classified.should_rotate_credential is False
        assert classified.should_fallback is True

    def test_context_flags_and_reset_extraction(self):
        classified = self._classify()
        ctx = classified.error_context or {}
        assert ctx.get("openrouter_free_daily") is True
        assert ctx.get("openrouter_free_daily_reset_ms") == "1783123200000"

    def test_reset_ms_feeds_guard(self, quota_guard_env):
        from agent.openrouter_free_quota_guard import (
            free_quota_remaining,
            record_free_quota_exhausted,
        )

        future_ms = str(int((time.time() + 5400) * 1000))
        record_free_quota_exhausted(
            error_context={
                "openrouter_free_daily": True,
                "openrouter_free_daily_reset_ms": future_ms,
            },
        )
        assert free_quota_remaining() == pytest.approx(5400, abs=10)

    def test_ordinary_429_still_rotates(self):
        """A generic OpenRouter 429 (no daily-quota marker) keeps the
        existing rotate-credential behavior."""
        from agent.error_classifier import FailoverReason, classify_api_error

        err = MockAPIError("HTTP 429: Rate limit exceeded", status_code=429)
        classified = classify_api_error(
            err, provider="openrouter", model="deepseek/deepseek-v4-flash",
        )
        assert classified.reason == FailoverReason.rate_limit
        assert classified.should_rotate_credential is True


class TestAuxiliaryClientGuard:
    def test_skips_free_model_when_breaker_armed(self, quota_guard_env, monkeypatch):
        from agent.auxiliary_client import _try_openrouter
        from agent.openrouter_free_quota_guard import record_free_quota_exhausted

        monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test-1234")
        record_free_quota_exhausted(
            error_context={
                "openrouter_free_daily_reset_ms": (time.time() + 3600) * 1000,
            },
        )

        client, model = _try_openrouter(model="google/gemma-4-31b-it:free")
        assert client is None and model is None

    def test_paid_model_unaffected_by_breaker(self, quota_guard_env, monkeypatch):
        from agent.auxiliary_client import _try_openrouter
        from agent.openrouter_free_quota_guard import record_free_quota_exhausted

        monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test-1234")
        record_free_quota_exhausted(
            error_context={
                "openrouter_free_daily_reset_ms": (time.time() + 3600) * 1000,
            },
        )

        client, model = _try_openrouter(model="deepseek/deepseek-v4-flash")
        assert client is not None
        assert model == "deepseek/deepseek-v4-flash"

    def test_free_model_allowed_when_healthy(self, quota_guard_env, monkeypatch):
        from agent.auxiliary_client import _try_openrouter

        monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test-1234")
        client, model = _try_openrouter(model="google/gemma-4-31b-it:free")
        assert client is not None
        assert model == "google/gemma-4-31b-it:free"

    def test_pool_recovery_records_breaker_instead_of_rotating(
        self, quota_guard_env, monkeypatch,
    ):
        """A free-daily 429 through the auxiliary pool-recovery path must
        arm the breaker and must NOT mark the credential exhausted (which
        would block paid models on the same key for an hour)."""
        from unittest.mock import MagicMock, patch

        from agent.auxiliary_client import _recover_provider_pool
        from agent.openrouter_free_quota_guard import free_quota_remaining

        exc = MockAPIError(
            "Error code: 429 - Rate limit exceeded: "
            "free-models-per-day-high-balance.",
            status_code=429,
            body=FREE_DAILY_BODY,
        )

        pool = MagicMock()
        pool.has_credentials.return_value = True
        with patch("agent.auxiliary_client.load_pool", return_value=pool):
            recovered = _recover_provider_pool("openrouter", exc)

        assert recovered is False
        pool.mark_exhausted_and_rotate.assert_not_called()
        assert free_quota_remaining() is not None
