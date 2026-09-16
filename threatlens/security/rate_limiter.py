from __future__ import annotations

import time
from collections import deque
from threading import Lock
from typing import Protocol, cast


class RateLimitExceeded(Exception):
    pass


class RateLimiter(Protocol):
    def check(self, key: str) -> None: ...


class SlidingWindowRateLimiter:
    """Thread-safe sliding-window rate limiter keyed by an arbitrary string."""

    def __init__(self, limit: int, window_seconds: float = 60.0) -> None:
        if limit <= 0:
            raise ValueError("limit must be positive")
        self._limit = limit
        self._window = window_seconds
        self._events: dict[str, deque[float]] = {}
        self._lock = Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            bucket = self._events.setdefault(key, deque())
            cutoff = now - self._window
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            if len(bucket) >= self._limit:
                return False
            bucket.append(now)
            return True

    def check(self, key: str) -> None:
        if not self.allow(key):
            raise RateLimitExceeded(f"rate limit exceeded for {key!r}")

    def remaining(self, key: str) -> int:
        now = time.monotonic()
        with self._lock:
            bucket = self._events.get(key)
            if not bucket:
                return self._limit
            cutoff = now - self._window
            active = sum(1 for t in bucket if t >= cutoff)
            return max(0, self._limit - active)

    def reset(self, key: str | None = None) -> None:
        with self._lock:
            if key is None:
                self._events.clear()
            else:
                self._events.pop(key, None)


class RedisRateLimiter:
    """Distributed fixed-window limiter for multi-worker deployments."""

    def __init__(self, url: str, limit: int, window_seconds: int = 60) -> None:
        try:
            import redis
        except ImportError as exc:
            raise RuntimeError("install the redis extra to use Redis rate limiting") from exc
        self._limit = limit
        self._window = window_seconds
        self._client = redis.Redis.from_url(url, decode_responses=True)
        self._client.ping()

    def check(self, key: str) -> None:
        bucket = f"threatlens:rate:{key}:{int(time.time()) // self._window}"
        count = cast(int, self._client.incr(bucket))
        if count == 1:
            self._client.expire(bucket, self._window + 1)
        if count > self._limit:
            raise RateLimitExceeded(f"rate limit exceeded for {key!r}")


class ToolBudget:
    """Per-alert tool call budget to prevent runaway agent loops."""

    def __init__(self, max_calls: int) -> None:
        self._max = max_calls
        self._used = 0
        self._lock = Lock()

    @property
    def max_calls(self) -> int:
        return self._max

    def consume(self) -> None:
        with self._lock:
            if self._used >= self._max:
                raise RateLimitExceeded(
                    f"tool-call budget exhausted ({self._max} calls)"
                )
            self._used += 1

    @property
    def used(self) -> int:
        with self._lock:
            return self._used

    @property
    def remaining(self) -> int:
        with self._lock:
            return max(0, self._max - self._used)
