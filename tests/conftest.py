from __future__ import annotations

import pytest


_ISOLATE_VARS = [
    "SHADOWGATE_CLIENT_KEY",
    "SHADOWGATE_ADMIN_KEY",
    "SHADOWGATE_RATE_LIMIT_PER_MINUTE",
    "SHADOWGATE_RATE_LIMIT_BURST",
]


@pytest.fixture(autouse=True)
def isolate_auth_env(monkeypatch):
    for var in _ISOLATE_VARS:
        monkeypatch.delenv(var, raising=False)

    from shadowgate.ratelimit import _reset_for_testing
    _reset_for_testing()
    yield
    _reset_for_testing()
