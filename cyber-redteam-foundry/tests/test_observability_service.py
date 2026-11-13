"""WP11: service reporter and Backboard error-rate alerting."""

import pytest

from cyberredteam.observability import hooks
from cyberredteam.observability.service import (
    BackboardErrorTracker,
    ServiceReporter,
    track_backboard_outcome,
)


class Sink(hooks.NoopMetrics):
    def __init__(self):
        self.alerts = []

    def alert(self, title, text, level="WARN"):
        self.alerts.append((title, text, level))


@pytest.fixture
def sink():
    s = Sink()
    hooks.set_metrics(s)
    yield s
    hooks.set_metrics(hooks.NoopMetrics())


def test_alert_fires_above_20_percent(sink):
    t = BackboardErrorTracker(min_samples=10)
    for _ in range(7):
        t.record(True)
    for _ in range(2):
        t.record(False)
    assert not sink.alerts  # below min samples
    t.record(False)  # 3/10 = 30%
    assert len(sink.alerts) == 1 and sink.alerts[0][2] == "ERROR"
    t.record(False)  # cooldown suppresses a repeat
    assert len(sink.alerts) == 1


def test_no_alert_at_or_below_threshold(sink):
    t = BackboardErrorTracker(min_samples=10)
    for _ in range(8):
        t.record(True)
    for _ in range(2):
        t.record(False)  # exactly 20%
    assert not sink.alerts


def test_window_expires_old_failures(sink):
    now = [0.0]
    t = BackboardErrorTracker(clock=lambda: now[0], min_samples=5)
    for _ in range(5):
        t.record(False)
    assert sink.alerts
    now[0] = 1000.0
    assert t.rate() == 0.0


def test_decorator_records_outcomes_and_reraises(monkeypatch):
    from cyberredteam.observability import service

    seen = []
    monkeypatch.setattr(service._tracker, "record", lambda ok: seen.append(ok))

    @track_backboard_outcome
    def f(x):
        if x:
            raise RuntimeError("x")
        return 1

    assert f(0) == 1
    with pytest.raises(RuntimeError):
        f(1)
    assert seen == [True, False]


def test_reporter_collects_providers_and_survives_bad_ones():
    got = []

    def bad():
        raise RuntimeError

    r = ServiceReporter(got.append, {"queue_depth": lambda: 3, "kill_switch": lambda: False,
                                     "active_campaigns": lambda: 2, "bad": bad},
                        tracker=BackboardErrorTracker())
    r.report_once()
    m = got[0]
    assert m["queue_depth"] == 3 and m["kill_switch"] == 0 and m["active_campaigns"] == 2
    assert "heartbeat" in m and "backboard_error_rate" in m and "bad" not in m


def test_reporter_thread_starts_and_stops():
    import threading

    ev, got = threading.Event(), []
    r = ServiceReporter(lambda m: (got.append(m), ev.set()), interval_s=0.01,
                        tracker=BackboardErrorTracker())
    r.start()
    assert ev.wait(2)
    r.stop()
    assert got


def test_backboard_request_failure_feeds_tracker(monkeypatch):
    import httpx

    from cyberredteam.llm.backboard import BackboardError, ChatBackboard
    from cyberredteam.observability import service

    seen = []
    monkeypatch.setattr(service._tracker, "record", lambda ok: seen.append(ok))
    model = ChatBackboard(api_key="k", transport=httpx.MockTransport(lambda r: httpx.Response(400)))
    with pytest.raises(BackboardError):
        model._post_message([])
    assert seen == [False]
