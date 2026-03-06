"""Tests for tv.app_config centralized configuration."""

from __future__ import annotations

import pytest

from tv.app_config import cfg, load, reset


class TestDefaults:
    """Default values must match the old hardcoded constants."""

    @pytest.mark.parametrize(
        "section,key,expected",
        [
            # timeouts
            ("timeouts", "pid_kill", 2.0),
            ("timeouts", "pid_kill_interval", 0.2),
            ("timeouts", "process", 30),
            ("timeouts", "net_command", 10),
            ("timeouts", "openvpn_init", 30),
            ("timeouts", "fortivpn_ppp", 20),
            ("timeouts", "singbox_iface", 15),
            ("timeouts", "fortivpn_gw_poll", 0.5),
            ("timeouts", "fortivpn_gw_attempts", 10),
            ("timeouts", "check_subprocess", 15),
            ("timeouts", "check_port", 5),
            ("timeouts", "check_ping", 3),
            ("timeouts", "check_dns", 10),
            ("timeouts", "check_http", 5),
            ("timeouts", "check_external_ip", 5),
            ("timeouts", "cert_generation", 15),
            ("timeouts", "cert_openssl", 5),
            ("timeouts", "cleanup_sleep", 1.0),
            ("timeouts", "ping_warmup", 2),
            ("timeouts", "ps_aux", 10),
            # paths
            ("paths", "log_dir", "logs"),
            ("paths", "temp_dir", "/tmp"),
            ("paths", "defaults_file", "config.toml"),
            ("paths", "main_log", "tunnelvault.log"),
            ("paths", "resolver_dir", "/etc/resolver"),
            # defaults
            ("defaults", "fortivpn_port", "44333"),
            ("defaults", "fortivpn_cert_mode", "auto"),
            ("defaults", "openvpn_config", "client.ovpn"),
            ("defaults", "singbox_config", "singbox.json"),
            ("defaults", "singbox_interface", "utun99"),
            ("defaults", "network_service", "Wi-Fi"),
            # display
            ("display", "route_table_lines", 30),
            ("display", "box_width", 60),
            # logging
            ("logging", "level", "DEBUG"),
            ("logging", "truncate_on_start", True),
        ],
    )
    def test_default_value(self, section, key, expected):
        assert getattr(getattr(cfg, section), key) == expected


class TestLoad:
    def test_partial_override_timeouts(self):
        load({"timeouts": {"openvpn_init": 45}})
        assert cfg.timeouts.openvpn_init == 45
        # Other timeouts unchanged
        assert cfg.timeouts.process == 30

    def test_unknown_keys_warns(self):
        import warnings

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            load({"timeouts": {"nonexistent_key": 999}})
        # No crash, no new attribute, but warns
        assert not hasattr(cfg.timeouts, "nonexistent_key")
        assert any("nonexistent_key" in str(x.message) for x in w)

    def test_unknown_section_warns(self):
        import warnings

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            load({"fantasy": {"key": "val"}})
        # No crash, but warns
        assert any("fantasy" in str(x.message) for x in w)

    def test_load_logging_section(self):
        load({"logging": {"level": "ERROR"}})
        assert cfg.logging.level == "ERROR"

    def test_load_all_sections(self):
        load(
            {
                "timeouts": {"process": 60},
                "paths": {"log_dir": "/var/log"},
                "defaults": {"fortivpn_port": "10443"},
                "display": {"box_width": 80},
                "logging": {"level": "WARN"},
            }
        )
        assert cfg.timeouts.process == 60
        assert cfg.paths.log_dir == "/var/log"
        assert cfg.defaults.fortivpn_port == "10443"
        assert cfg.display.box_width == 80
        assert cfg.logging.level == "WARN"

    def test_empty_app_section_is_noop(self):
        original_timeout = cfg.timeouts.process
        load({})
        assert cfg.timeouts.process == original_timeout

    def test_none_subsection_ignored(self):
        load({"timeouts": None})
        # No crash


class TestReset:
    def test_reset_restores_defaults(self):
        load({"timeouts": {"process": 999}, "paths": {"log_dir": "/custom"}})
        assert cfg.timeouts.process == 999
        reset()
        assert cfg.timeouts.process == 30
        assert cfg.paths.log_dir == "logs"

    def test_reset_preserves_identity(self):
        original_id = id(cfg)
        load({"timeouts": {"process": 999}})
        reset()
        assert id(cfg) == original_id
