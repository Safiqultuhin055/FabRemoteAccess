"""In-process sliding-window rate limiter.

SINGLE INSTANCE ONLY: counters live in this process's memory, so limits are per process
and reset on restart. Running several backend instances needs a shared store (e.g. Redis)
behind the same interface. Counters that must survive restarts (failed-login lockout) are
kept in the database instead.
"""

from __future__ import annotations

import hashlib
import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass


@dataclass(frozen=True)
class Limit:
    max_hits: int
    window_seconds: int


@dataclass(frozen=True)
class RateLimits:
    """Initial values from docs/API_CONTRACTS.md section 6."""
    login_per_account_ip: Limit = Limit(5, 60)
    login_per_ip: Limit = Limit(20, 60)
    refresh_per_token: Limit = Limit(30, 60)
    refresh_per_ip: Limit = Limit(60, 60)
    invitation_accept_per_ip: Limit = Limit(10, 60)
    invitation_create_per_admin: Limit = Limit(30, 60)
    device_registration_per_user: Limit = Limit(10, 60)
    device_challenge_per_device: Limit = Limit(30, 60)
    device_proof_per_device: Limit = Limit(30, 60)
    device_rotation_per_device: Limit = Limit(5, 60)


class RateLimiter:
    def __init__(self, max_keys: int = 100_000, monotonic=time.monotonic):
        self._hits: OrderedDict[str, deque[float]] = OrderedDict()
        self._lock = threading.Lock()
        self._max_keys = max_keys
        self._monotonic = monotonic

    @staticmethod
    def key(*parts: str) -> str:
        """Hash identifying parts (emails, tokens) so they are not held in memory in clear."""
        return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()

    def hit(self, key: str, limit: Limit) -> int | None:
        """Record an attempt. Returns None if allowed, else seconds until the next attempt is allowed."""
        now = self._monotonic()
        with self._lock:
            window = self._hits.pop(key, None) or deque()
            while window and window[0] <= now - limit.window_seconds:
                window.popleft()
            if len(window) >= limit.max_hits:
                self._hits[key] = window
                return max(1, int(window[0] + limit.window_seconds - now + 0.999))
            window.append(now)
            self._hits[key] = window
            while len(self._hits) > self._max_keys:   # bound memory; evict least recently used
                self._hits.popitem(last=False)
            return None

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()
