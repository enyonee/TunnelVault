"""Tests for tv.ui: terminal output and summary table."""

from __future__ import annotations

from tv import ui


# =========================================================================
# Positive: helpers
# =========================================================================


class TestVisibleLen:
    def test_plain_text(self):
        assert ui._visible_len("hello") == 5

    def test_ansi_stripped(self):
        colored = f"{ui.RED}hello{ui.NC}"
        assert ui._visible_len(colored) == 5

    def test_empty(self):
        assert ui._visible_len("") == 0

    def test_only_ansi(self):
        assert ui._visible_len(f"{ui.BOLD}{ui.NC}") == 0


# =========================================================================
# Positive: summary table
# =========================================================================


class TestPrintSummary:
    def test_renders_without_error(self, capsys):
        ui.print_summary(
            tunnels=[
                ("FortiVPN", True, "ppp0"),
                ("OpenVPN", True, "1.2.3.4"),
                ("sing-box", False, "не подключен"),
            ],
            checks=[
                ("host:8080", "ok", "порт открыт"),
                ("host:1521", "fail", "порт закрыт"),
                ("DNS", "skip", "пропуск"),
            ],
            log_paths={"forti": "/tmp/forti.log", "debug": "/tmp/debug.log"},
        )
        out = capsys.readouterr().out
        assert "CONNECTION SUMMARY" in out
        assert "FortiVPN" in out
        assert "CHECKS" in out
        assert "1/3" in out  # passed считает только "ok" (skip не в счёт)

    def test_all_ok_shows_correct_count(self, capsys):
        checks = [("c1", "ok", "ok"), ("c2", "ok", "ok")]
        ui.print_summary(
            tunnels=[("VPN", True, "up")],
            checks=checks,
            log_paths={},
        )
        out = capsys.readouterr().out
        assert "2/2" in out

    def test_empty_checks(self, capsys):
        """Нет проверок - не падает."""
        ui.print_summary(tunnels=[], checks=[], log_paths={})
        out = capsys.readouterr().out
        assert "0/0" in out


# =========================================================================
# Negative / inverse: edge cases
# =========================================================================


class TestSummaryInverse:
    def test_long_labels_dont_break_box(self, capsys):
        """Очень длинные лейблы не ломают рамку."""
        long_label = "x" * 80
        ui.print_summary(
            tunnels=[(long_label, True, "detail")],
            checks=[(long_label, "ok", "ok")],
            log_paths={},
        )
        out = capsys.readouterr().out
        # Не упал - уже хорошо. Проверим что рамка присутствует
        assert "┏" in out
        assert "┛" in out

    def test_unicode_in_labels(self, capsys):
        """Unicode в лейблах не ломает вывод."""
        ui.print_summary(
            tunnels=[("ВПН Кириллица", True, "ок")],
            checks=[("проверка ✅", "ok", "ок")],
            log_paths={"лог": "/tmp/лог.log"},
        )
        out = capsys.readouterr().out
        assert "ВПН Кириллица" in out


# =========================================================================
# Proto line (plugin display names in logo)
# =========================================================================


class TestBuildProtoLine:
    def test_contains_display_names(self):
        line = ui._build_proto_line()
        # Strip ANSI to check content
        plain = ui._ANSI_RE.sub("", line)
        assert "OpenVPN" in plain
        assert "FortiVPN" in plain
        assert "sing-box" in plain

    def test_does_not_use_raw_type_names(self):
        """Should use display_name, not type key (e.g. 'singbox')."""
        line = ui._build_proto_line()
        plain = ui._ANSI_RE.sub("", line)
        # 'singbox' is the registry key, 'sing-box' is the display name
        assert "singbox" not in plain
