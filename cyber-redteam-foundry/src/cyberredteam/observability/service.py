"""Service telemetry (WP11): periodic reporter and Backboard error-rate tracker."""

from __future__ import annotations

import collections
import functools
import logging
import threading
import time
from collections.abc import Callable
from typing import Any

from cyberredteam.observability import hooks

logger = logging.getLogger(__name__)

Provider = Callable[[], Any]


class BackboardErrorTracker:
    """Rolling-window error rate; alerts when it exceeds the threshold."""

    def __init__(
        self,
        window_s: float = 300.0,
        threshold: float = 0.20,
        min_samples: int = 10,
        cooldown_s: float = 300.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.window_s, self.threshold = window_s, threshold
        self.min_samples, self.cooldown_s, self._clock = min_samples, cooldown_s, clock
        self._events: collections.deque[tuple[float, bool]] = collections.deque()
        self._last_alert: float | None = None
        self._lock = threading.Lock()

    def _trim(self, now: float) -> None:
        while self._events and now - self._events[0][0] > self.window_s:
            self._events.popleft()

    def record(self, ok: bool) -> bool:
        """Record one call; returns True if this call fired an alert."""
        now = self._clock()
        with self._lock:
            self._events.append((now, ok))
            self._trim(now)
            rate, n = self._rate_locked()
            should = (
                n >= self.min_samples
                and rate > self.threshold
                and (self._last_alert is None or now - self._last_alert >= self.cooldown_s)
            )
            if should:
                self._last_alert = now
        if should:
            try:
                hooks.get_metrics().alert(
                    "Backboard error rate high",
                    f"{rate:.0%} of {n} Backboard calls failed in the last "
                    f"{int(self.window_s // 60)} min (threshold {self.threshold:.0%}).",
                    "ERROR",
                )
            except Exception as exc:
                logger.warning("backboard alert failed: %s", exc)
        return should

    def _rate_locked(self) -> tuple[float, int]:
        n = len(self._events)
        if n == 0:
            return 0.0, 0
        return sum(1 for _, ok in self._events if not ok) / n, n

    def rate(self) -> float:
        with self._lock:
            self._trim(self._clock())
            return self._rate_locked()[0]


_tracker = BackboardErrorTracker()


def get_backboard_tracker() -> BackboardErrorTracker:
    return _tracker


def track_backboard_outcome(fn: Callable[..., Any]) -> Callable[..., Any]:
    """Decorator: record success/failure of a Backboard request (never raises)."""

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            result = fn(*args, **kwargs)
        except BaseException:
            _safe_record(False)
            raise
        _safe_record(True)
        return result

    return wrapper


def _safe_record(ok: bool) -> None:
    try:
        _tracker.record(ok)
    except Exception:
        pass


class ServiceReporter:
    """Logs service health every ``interval_s`` seconds from injectable providers.

    Providers are zero-arg callables: ``queue_depth``, ``active_campaigns``,
    ``kill_switch`` (bool), plus any extra names. ``heartbeat`` (unix time) and
    ``backboard_error_rate`` are always included. A provider that raises is
    skipped for that tick.
    """

    def __init__(
        self,
        sink: Callable[[dict[str, float]], None],
        providers: dict[str, Provider] | None = None,
        interval_s: float = 60.0,
        tracker: BackboardErrorTracker | None = None,
    ) -> None:
        self.sink, self.providers = sink, dict(providers or {})
        self.interval_s = interval_s
        self.tracker = tracker or _tracker
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def collect(self) -> dict[str, float]:
        out: dict[str, float] = {"heartbeat": time.time()}
        for name, fn in self.providers.items():
            try:
                out[name] = float(fn())
            except Exception as exc:
                logger.debug("service provider %s failed: %s", name, exc)
        out["backboard_error_rate"] = self.tracker.rate()
        return out

    def report_once(self) -> None:
        try:
            self.sink(self.collect())
        except Exception as exc:
            logger.warning("service report failed: %s", exc)

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._loop, name="canary-service-reporter",
                                        daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        while not self._stop.wait(self.interval_s):
            self.report_once()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None
