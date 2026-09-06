"""Fixtures every test gets.

There is one of these because the API's rate limiter is in-process and counts
per identity per wall-clock minute — and a whole suite hitting the shared app
arrives as a single identity. That made the request budget a resource shared
across test modules: adding tests to `tests/integration/test_api.py` failed
assertions in `tests/test_auth.py` with a 429, and only in CI, where the suite
runs fast enough for it all to land inside one minute.

Order-dependent and machine-dependent is the worst shape a test failure can
have, so every test starts with a clean budget. The limiter itself is not
weakened: `tests/test_security.py` builds its own app and still proves the
limit works.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _fresh_rate_limit_budget():
    from bishop.api.security import reset_rate_limits

    reset_rate_limits()
    yield
    reset_rate_limits()
