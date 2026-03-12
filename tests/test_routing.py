"""Tests for tv.routing: target parsing and merge."""

from __future__ import annotations

import pytest

from tv.routing import (
    parse_targets,
    merge_targets_into_config,
    validate_target,
    ParsedTargets,
)
from tv.vpn.base import TunnelConfig


# =========================================================================
# parse_targets
# =========================================================================


class TestParseTargets:
    @pytest.mark.parametrize(
        "inputs,domains,networks,hosts",
        [
            (["*.alpha.local"], ["alpha.local"], [], []),
            (["10.0.0.0/8"], [], ["10.0.0.0/8"], []),
            (["192.168.1.1"], [], [], ["192.168.1.1"]),
            (["git.test.local"], [], [], ["git.test.local"]),
            ([], [], [], []),
            (
                ["  *.alpha.local  ", "  10.0.0.0/8  "],
                ["alpha.local"],
                ["10.0.0.0/8"],
                [],
            ),
            (["", "  ", "10.0.0.0/8"], [], ["10.0.0.0/8"], []),
            (["999.999.999.999/99"], [], [], []),
            (
                ["*.a.local", "*.b.local", "*.c.local"],
                ["a.local", "b.local", "c.local"],
                [],
                [],
            ),
            (["10.0.0.1/8"], [], ["10.0.0.1/8"], []),
            (["999.999.999.999"], [], [], []),
            (
                ["999.0.0.1", "10.0.0.1", "*.alpha.local"],
                ["alpha.local"],
                [],
                ["10.0.0.1"],
            ),
        ],
    )
    def test_parse(self, inputs, domains, networks, hosts):
        result = parse_targets(inputs)
        assert result.domains == domains
        assert result.networks == networks
        assert result.hosts == hosts

    def test_mixed_input(self):
        result = parse_targets(
            [
                "*.asup.local",
                "10.0.0.0/8",
                "192.168.77.0/24",
                "192.168.1.1",
                "git.test.local",
            ]
        )
        assert result.domains == ["asup.local"]
        assert result.networks == ["10.0.0.0/8", "192.168.77.0/24"]
        assert result.hosts == ["192.168.1.1", "git.test.local"]


# =========================================================================
# validate_target
# =========================================================================


class TestValidateTarget:
    @pytest.mark.parametrize(
        "target,expected_kind,err_contains",
        [
            ("10.0.0.0/8", "network", ""),
            ("192.168.1.1", "host", ""),
            ("*.alpha.local", "domain", ""),
            ("git.test.local", "hostname", ""),
            ("999.999.999.999/99", "", "invalid CIDR"),
            ("999.0.0.1", "", "invalid IP"),
            ("*.localhost", "", "must contain a dot"),
            ("!!!not-valid!!!", "", "unrecognized format"),
            ("", "", ""),
            ("  10.0.0.0/8  ", "network", ""),
            ("myserver", "hostname", ""),
        ],
    )
    def test_validate(self, target, expected_kind, err_contains):
        kind, err = validate_target(target)
        assert kind == expected_kind
        if err_contains:
            assert err_contains in err
        else:
            assert err == ""


# =========================================================================
# merge_targets_into_config
# =========================================================================


class TestMergeTargets:
    def test_merge_into_empty(self):
        tcfg = TunnelConfig()
        parsed = ParsedTargets(
            networks=["10.0.0.0/8"],
            hosts=["1.2.3.4"],
            domains=["alpha.local"],
        )
        merge_targets_into_config(tcfg, parsed)
        assert tcfg.routes["networks"] == ["10.0.0.0/8"]
        assert tcfg.routes["hosts"] == ["1.2.3.4"]
        assert tcfg.dns["domains"] == ["alpha.local"]

    def test_no_duplicates(self):
        tcfg = TunnelConfig(
            routes={"networks": ["10.0.0.0/8"], "hosts": ["1.2.3.4"]},
            dns={"domains": ["alpha.local"]},
        )
        parsed = ParsedTargets(
            networks=["10.0.0.0/8", "172.16.0.0/12"],
            hosts=["1.2.3.4", "5.6.7.8"],
            domains=["alpha.local", "new.local"],
        )
        merge_targets_into_config(tcfg, parsed)
        assert tcfg.routes["networks"] == ["10.0.0.0/8", "172.16.0.0/12"]
        assert tcfg.routes["hosts"] == ["1.2.3.4", "5.6.7.8"]
        assert tcfg.dns["domains"] == ["alpha.local", "new.local"]

    def test_empty_parsed_noop(self):
        tcfg = TunnelConfig(
            routes={"networks": ["10.0.0.0/8"]},
        )
        merge_targets_into_config(tcfg, ParsedTargets())
        assert tcfg.routes == {"networks": ["10.0.0.0/8"]}

    def test_merge_only_new(self):
        tcfg = TunnelConfig(routes={"networks": ["10.0.0.0/8"]})
        parsed = ParsedTargets(networks=["172.16.0.0/12"])
        merge_targets_into_config(tcfg, parsed)
        assert tcfg.routes["networks"] == ["10.0.0.0/8", "172.16.0.0/12"]
