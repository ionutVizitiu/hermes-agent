"""Cross-session daily-quota guard for OpenRouter ``:free`` models.

OpenRouter enforces an account-wide daily request cap across ALL free
(``:free``-suffixed) models — e.g. ``free-models-per-day`` /
``free-models-per-day-high-balance`` (1000 requests/day for accounts with
a credit balance). Once the bucket is empty, every free-model request 429s
until the daily window resets (midnight UTC), so:

  * retry-with-backoff can never recover within a turn, and
  * rotating credentials on the same account can't help, and
  * marking the credential exhausted poisons the pool for PAID models on
    the same key — which is exactly the fallback that would succeed.

This guard mirrors ``agent.nous_rate_guard``: the first daily-quota 429
records the reset time to a shared file so ALL sessions (CLI, gateway,
cron, kanban workers, auxiliary tasks) skip free models until the window
resets, instead of each one burning its full retry budget.

State lives under the ROOT Hermes home (not the profile home): the quota
is account-level and every profile shares the same OpenRouter key, so one
profile's breaker must be visible to all of them.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import time
from typing import Any, Mapping, Optional

from utils import atomic_replace

# Reuse the human-readable duration formatter so status messages stay
# consistent with the Nous guard ("resets in 5h 12m").
from agent.nous_rate_guard import format_remaining  # noqa: F401  (re-export)

logger = logging.getLogger(__name__)

_STATE_SUBDIR = "rate_limits"
_STATE_FILENAME = "openrouter_free.json"

# The marker OpenRouter puts in the 429 body when the account-wide free-model
# daily bucket is exhausted (covers "free-models-per-day" and
# "free-models-per-day-high-balance").
FREE_DAILY_QUOTA_MARKER = "free-models-per-day"

# The daily window resets at midnight UTC. Clamp whatever reset value we
# parse to at most a bit over one day so a garbage header can't brick free
# models for a week; floor it so clock skew can't produce a useless breaker.
_MAX_COOLDOWN_SECONDS = 26 * 3600.0
_MIN_COOLDOWN_SECONDS = 60.0


def is_free_model(model: Any) -> bool:
    """Whether a model slug is an OpenRouter free-tier variant."""
    return isinstance(model, str) and model.strip().lower().endswith(":free")


def _state_path() -> str:
    """Return the path to the shared quota state file (root Hermes home)."""
    try:
        from hermes_constants import get_default_hermes_root
        base = str(get_default_hermes_root())
    except ImportError:
        base = os.path.join(os.path.expanduser("~"), ".hermes")
    return os.path.join(base, _STATE_SUBDIR, _STATE_FILENAME)


def _seconds_until_next_utc_midnight(now: float) -> float:
    """Daily free-model buckets reset at midnight UTC."""
    return 86400.0 - (now % 86400.0)


def _parse_reset_epoch_ms(value: Any) -> Optional[float]:
    """Parse OpenRouter's ``X-RateLimit-Reset`` (epoch **milliseconds**).

    Returns an epoch-seconds float, or None when unparseable/implausible.
    """
    try:
        raw = float(value)
    except (TypeError, ValueError):
        return None
    if raw <= 0:
        return None
    # Values this large are unambiguously milliseconds (epoch-seconds won't
    # exceed 1e11 for ~1100 years).
    if raw > 1e11:
        raw = raw / 1000.0
    return raw


def _reset_ms_from_headers(headers: Optional[Mapping[str, str]]) -> Optional[float]:
    """Extract the reset epoch (seconds) from response headers, if present."""
    if not headers:
        return None
    lowered = {str(k).lower(): v for k, v in headers.items()}
    return _parse_reset_epoch_ms(lowered.get("x-ratelimit-reset"))


def record_free_quota_exhausted(
    *,
    headers: Optional[Mapping[str, str]] = None,
    error_context: Optional[dict[str, Any]] = None,
) -> None:
    """Record that the OpenRouter free-model daily quota is exhausted.

    Reset time is taken from (in priority order):
      1. ``error_context["openrouter_free_daily_reset_ms"]`` — parsed from
         the 429 body's ``metadata.headers['X-RateLimit-Reset']`` by the
         error classifier (epoch milliseconds).
      2. The HTTP response's own ``X-RateLimit-Reset`` header.
      3. Next midnight UTC (the documented daily-window boundary).
    """
    now = time.time()
    reset_at: Optional[float] = None

    if isinstance(error_context, dict):
        reset_at = _parse_reset_epoch_ms(
            error_context.get("openrouter_free_daily_reset_ms")
        )

    if reset_at is None:
        reset_at = _reset_ms_from_headers(headers)

    if reset_at is None or reset_at <= now:
        reset_at = now + _seconds_until_next_utc_midnight(now)

    reset_at = min(reset_at, now + _MAX_COOLDOWN_SECONDS)
    reset_at = max(reset_at, now + _MIN_COOLDOWN_SECONDS)

    path = _state_path()
    try:
        state_dir = os.path.dirname(path)
        os.makedirs(state_dir, exist_ok=True)

        state = {
            "reset_at": reset_at,
            "recorded_at": now,
            "reset_seconds": reset_at - now,
        }

        fd, tmp_path = tempfile.mkstemp(dir=state_dir, suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(state, f)
            atomic_replace(tmp_path, path)
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

        logger.info(
            "OpenRouter free-model daily quota recorded as exhausted: "
            "resets in %.0fs (at %.0f)",
            reset_at - now, reset_at,
        )
    except Exception as exc:
        logger.debug("Failed to write OpenRouter free quota state: %s", exc)


def free_quota_remaining() -> Optional[float]:
    """Seconds until the free-model daily quota resets, or None if healthy."""
    path = _state_path()
    try:
        with open(path, encoding="utf-8") as f:
            state = json.load(f)
        reset_at = state.get("reset_at", 0)
        remaining = reset_at - time.time()
        if remaining > 0:
            return remaining
        # Window has reset — clean up so the check stays cheap.
        try:
            os.unlink(path)
        except OSError:
            pass
        return None
    except (FileNotFoundError, json.JSONDecodeError, KeyError, TypeError):
        return None


def clear_free_quota() -> None:
    """Clear the breaker (a free-model request succeeded, so it has reset)."""
    try:
        os.unlink(_state_path())
    except FileNotFoundError:
        pass
    except OSError as exc:
        logger.debug("Failed to clear OpenRouter free quota state: %s", exc)
