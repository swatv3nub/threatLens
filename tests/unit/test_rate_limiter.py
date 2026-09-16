from __future__ import annotations

import pytest

from threatlens.security.rate_limiter import (
    RateLimitExceeded,
    SlidingWindowRateLimiter,
    ToolBudget,
)


def test_rate_limiter_allows_within_limit() -> None:
    limiter = SlidingWindowRateLimiter(limit=3)
    for _ in range(3):
        assert limiter.allow("client")
    assert not limiter.allow("client")


def test_rate_limiter_check_raises() -> None:
    limiter = SlidingWindowRateLimiter(limit=1)
    limiter.check("k")
    with pytest.raises(RateLimitExceeded):
        limiter.check("k")


def test_rate_limiter_per_key() -> None:
    limiter = SlidingWindowRateLimiter(limit=1)
    assert limiter.allow("a")
    assert limiter.allow("b")


def test_tool_budget() -> None:
    budget = ToolBudget(2)
    budget.consume()
    budget.consume()
    assert budget.remaining == 0
    with pytest.raises(RateLimitExceeded):
        budget.consume()
