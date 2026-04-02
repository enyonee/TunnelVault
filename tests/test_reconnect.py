"""Tests for scheduled reconnect config and timer logic."""

from __future__ import annotations

import datetime

import pytest

from tv.app_config import Reconnect, cfg, load_reconnect, reset


class TestReconnectConfig:
    """Test [reconnect] section parsing."""

    def setup_method(self):
        reset()

    def test_default_disabled(self):
        assert cfg.reconnect.enabled is False
        assert cfg.reconnect.interval == ""
        assert cfg.reconnect.schedule == ""
        assert cfg.reconnect.tunnels is None

    def test_load_interval(self):
        load_reconnect({"enabled": True, "interval": "6h"})
        assert cfg.reconnect.enabled is True
        assert cfg.reconnect.interval == "6h"

    def test_load_schedule(self):
        load_reconnect({"enabled": True, "schedule": "03:00"})
        assert cfg.reconnect.enabled is True
        assert cfg.reconnect.schedule == "03:00"

    def test_load_tunnels(self):
        load_reconnect({"enabled": True, "interval": "1h", "tunnels": ["fortivpn"]})
        assert cfg.reconnect.tunnels == ["fortivpn"]

    def test_unknown_key_warns(self):
        with pytest.warns(UserWarning, match="Unknown key in \\[reconnect\\]: 'foo'"):
            load_reconnect({"foo": "bar"})

    def test_interval_and_schedule_warns(self):
        with pytest.warns(UserWarning, match="both 'interval' and 'schedule'"):
            load_reconnect({"enabled": True, "interval": "6h", "schedule": "03:00"})

    def test_empty_dict_noop(self):
        load_reconnect({})
        assert cfg.reconnect.enabled is False


class TestIntervalSeconds:
    """Test Reconnect.interval_seconds() parsing."""

    def test_hours(self):
        r = Reconnect(interval="6h")
        assert r.interval_seconds() == 21600

    def test_minutes(self):
        r = Reconnect(interval="30m")
        assert r.interval_seconds() == 1800

    def test_seconds(self):
        r = Reconnect(interval="120s")
        assert r.interval_seconds() == 120

    def test_bare_number(self):
        r = Reconnect(interval="3600")
        assert r.interval_seconds() == 3600

    def test_empty(self):
        r = Reconnect(interval="")
        assert r.interval_seconds() is None

    def test_fractional_hours(self):
        r = Reconnect(interval="1.5h")
        assert r.interval_seconds() == 5400

    def test_invalid_raises(self):
        r = Reconnect(interval="abc")
        with pytest.raises(ValueError, match="Invalid reconnect interval"):
            r.interval_seconds()

    def test_empty_suffix_raises(self):
        r = Reconnect(interval="h")
        with pytest.raises(ValueError, match="Invalid reconnect interval"):
            r.interval_seconds()


class TestNextScheduleTime:
    """Test _next_schedule_time helper."""

    def test_future_today(self):
        from tunnelvault import _next_schedule_time

        fake_now = datetime.datetime(2026, 3, 31, 10, 0, 0)
        seconds = _next_schedule_time("14:00", _now=fake_now)
        assert seconds == 14400  # exactly 4h

    def test_past_today_wraps_to_tomorrow(self):
        from tunnelvault import _next_schedule_time

        fake_now = datetime.datetime(2026, 3, 31, 15, 0, 0)
        seconds = _next_schedule_time("03:00", _now=fake_now)
        assert seconds == 43200  # exactly 12h

    def test_exact_now_wraps_to_tomorrow(self):
        from tunnelvault import _next_schedule_time

        fake_now = datetime.datetime(2026, 3, 31, 3, 0, 0)
        seconds = _next_schedule_time("03:00", _now=fake_now)
        assert seconds == 86400  # exactly 24h
