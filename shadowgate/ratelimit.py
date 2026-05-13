from __future__ import annotations

import os
import time
from collections import deque
from typing import Any

_call_times: deque[float] = deque()
_WINDOW = 60.0


def _get_limits() -> tuple[int, int]:
    try:
        per_minute = int(os.environ.get("SHADOWGATE_RATE_LIMIT_PER_MINUTE", "0") or "0")
    except ValueError:
        per_minute = 0
    try:
        burst = int(os.environ.get("SHADOWGATE_RATE_LIMIT_BURST", "0") or "0")
    except ValueError:
        burst = 0
    return max(0, per_minute), max(0, burst)


def check_rate_limit() -> dict[str, Any]:
    per_minute, _burst = _get_limits()
    if per_minute <= 0:
        return {"ok": True, "rate_limited": False}

    now = time.monotonic()
    cutoff = now - _WINDOW

    while _call_times and _call_times[0] < cutoff:
        _call_times.popleft()

    count = len(_call_times)

    if count >= per_minute:
        retry_after = int(_WINDOW - (now - _call_times[0])) + 1 if _call_times else int(_WINDOW)
        return {
            "ok": False,
            "rate_limited": True,
            "error": "Rate limit exceeded. Retry after the window resets.",
            "limit_per_minute": per_minute,
            "calls_in_window": count,
            "retry_after_seconds": retry_after,
        }

    _call_times.append(now)
    return {
        "ok": True,
        "rate_limited": False,
        "calls_in_window": count + 1,
        "limit_per_minute": per_minute,
    }


def _reset_for_testing() -> None:
    _call_times.clear()
