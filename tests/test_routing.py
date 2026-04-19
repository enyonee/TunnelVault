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
# IPv6 parsing (PR#2)
# =========================================================================


class TestParseTargetsIPv6:
    """IPv6 CIDR/addresses парсятся в networks/hosts.

    КРИТИЧНО: существующие IPv4 тесты не должны сломаться - IPv6 regex
    добавлены ПЕРЕД hostname fallback, но ПОСЛЕ IPv4 regex (H4).
    """

    @pytest.mark.parametrize(
        "inputs,domains,networks,hosts",
        [
            # CIDR IPv6
            (["2001:db8::/32"], [], ["2001:db8::/32"], []),
            (["fe80::/10"], [], ["fe80::/10"], []),
            (["::/0"], [], ["::/0"], []),
            # Адреса IPv6
            (["2001:db8::1"], [], [], ["2001:db8::1"]),
            (["fe80::1"], [], [], ["fe80::1"]),
            (["::1"], [], [], ["::1"]),
            # Full form
            (
                ["2001:0db8:85a3:0000:0000:8a2e:0370:7334"],
                [],
                [],
                ["2001:0db8:85a3:0000:0000:8a2e:0370:7334"],
            ),
            # Невалидный IPv6 prefix - попадает в hostname fallback (existing flow)
            (["2001:db8::gggg"], [], [], ["2001:db8::gggg"]),
            # Невалидный IPv6 CIDR (prefix > 128) - отвергается, пустой результат
            (["2001:db8::/130"], [], [], []),
            # Mixed IPv4 + IPv6
            (
                ["10.0.0.0/8", "2001:db8::/32", "192.168.1.1", "fe80::1"],
                [],
                ["10.0.0.0/8", "2001:db8::/32"],
                ["192.168.1.1", "fe80::1"],
            ),
        ],
    )
    def test_parse_ipv6(self, inputs, domains, networks, hosts):
        result = parse_targets(inputs)
        assert result.domains == domains
        assert result.networks == networks
        assert result.hosts == hosts

    def test_ipv4_pattern_preserved(self):
        """Backward compat: '10.0.0.0/8' идентично pre-PR (IPv4 ветка срабатывает первой)."""
        result = parse_targets(["10.0.0.0/8"])
        assert result.networks == ["10.0.0.0/8"]
        assert result.hosts == []
        assert result.domains == []

    def test_hostname_with_colon_in_middle_rejected(self):
        """'host:port' не IPv6 (есть нехекс символы) - попадает в hostname.

        Regex IPv6_RE требует только [0-9a-fA-F:], поэтому 'server:port' не match.
        Но ':' в такой строке есть - hostname regex тоже не match - попадёт в hosts
        как bare entry (существующее поведение)."""
        result = parse_targets(["server:8080"])
        # 'server:8080' - не IPv4, не IPv6 (есть 's', 'r', 'v', не hex).
        # Проходит как hostname fallback (bare string - engine попробует resolve).
        assert "server:8080" in result.hosts

    def test_ipv6_before_hostname_fallback(self):
        """'2001:db8::1' должен попасть в hosts как IPv6, а НЕ bare hostname."""
        result = parse_targets(["2001:db8::1"])
        assert result.hosts == ["2001:db8::1"]
        assert result.networks == []


class TestValidateTargetIPv6:
    @pytest.mark.parametrize(
        "target,expected_kind,err_contains",
        [
            ("2001:db8::/32", "network", ""),
            ("2001:db8::1", "host", ""),
            ("fe80::1", "host", ""),
            ("::1", "host", ""),
            ("::/0", "network", ""),
            ("2001:db8::/130", "", "invalid CIDR"),
            ("2001:db8::gggg", "", "unrecognized"),
        ],
    )
    def test_validate_ipv6(self, target, expected_kind, err_contains):
        kind, err = validate_target(target)
        assert kind == expected_kind
        if err_contains:
            assert err_contains in err
        else:
            assert err == ""


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
