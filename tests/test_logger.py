"""Tests for tv.logger."""

from __future__ import annotations

from pathlib import Path

from tv.app_config import cfg
from tv.logger import Logger


# =========================================================================
# Positive
# =========================================================================


class TestLogger:
    def test_creates_empty_log(self, tmp_path: Path):
        log = Logger(tmp_path / "test.log")
        assert log.log_path.exists()
        assert log.log_path.read_text() == ""

    def test_log_appends(self, tmp_path: Path):
        log = Logger(tmp_path / "test.log")
        log.log("INFO", "first")
        log.log("WARN", "second")
        content = log.log_path.read_text()
        assert "[INFO] first" in content
        assert "[WARN] second" in content
        assert content.index("first") < content.index("second")

    def test_log_has_timestamp(self, tmp_path: Path):
        log = Logger(tmp_path / "test.log")
        log.log("INFO", "timestamped")
        line = log.log_path.read_text().strip()
        # Format: [2026-02-20 12:31:18.123] [INFO] ...
        assert line.startswith("[20")
        assert "] [INFO]" in line

    def test_log_lines(self, tmp_path: Path):
        log = Logger(tmp_path / "test.log")
        log.log_lines("DEBUG", "line1\nline2\nline3")
        content = log.log_path.read_text()
        assert content.count("[DEBUG]") == 3


# =========================================================================
# Negative / inverse
# =========================================================================


class TestLoggerInverse:
    def test_truncates_existing_log(self, tmp_path: Path):
        """Новый Logger ПЕРЕЗАТИРАЕТ существующий лог."""
        path = tmp_path / "test.log"
        path.write_text("old content\n")
        Logger(path)
        assert path.read_text() == ""

    def test_log_env_with_mock_net(self, tmp_path: Path, mock_net):
        """log_env не падает с mock NetManager."""
        log = Logger(tmp_path / "test.log")
        log.log_env(mock_net, tmp_path)
        content = log.log_path.read_text()
        assert "Environment snapshot" in content
        assert "/Snapshot" in content

    def test_empty_message(self, tmp_path: Path):
        """Пустое сообщение - не падает."""
        log = Logger(tmp_path / "test.log")
        log.log("INFO", "")
        assert "[INFO]" in log.log_path.read_text()


# =========================================================================
# Log level filtering
# =========================================================================


class TestLogLevelFiltering:
    def test_level_error_filters_info(self, tmp_path: Path):
        """level=ERROR -> INFO не попадает в файл."""
        cfg.logging.level = "ERROR"
        log = Logger(tmp_path / "test.log")
        log.log("INFO", "should be filtered")
        log.log("ERROR", "should appear")
        content = log.log_path.read_text()
        assert "should be filtered" not in content
        assert "should appear" in content

    def test_level_warn_filters_info_passes_error(self, tmp_path: Path):
        """level=WARN -> INFO отфильтрован, WARN и ERROR проходят."""
        cfg.logging.level = "WARN"
        log = Logger(tmp_path / "test.log")
        log.log("INFO", "info msg")
        log.log("WARN", "warn msg")
        log.log("ERROR", "error msg")
        content = log.log_path.read_text()
        assert "info msg" not in content
        assert "warn msg" in content
        assert "error msg" in content

    def test_level_debug_passes_everything(self, tmp_path: Path):
        """level=DEBUG -> всё проходит."""
        cfg.logging.level = "DEBUG"
        log = Logger(tmp_path / "test.log")
        log.log("DEBUG", "debug msg")
        log.log("INFO", "info msg")
        log.log("WARN", "warn msg")
        content = log.log_path.read_text()
        assert "debug msg" in content
        assert "info msg" in content
        assert "warn msg" in content


# =========================================================================
# Format preservation
# =========================================================================


class TestFormatPreservation:
    def test_warn_format_not_warning(self, tmp_path: Path):
        """Формат [WARN] а не [WARNING]."""
        log = Logger(tmp_path / "test.log")
        log.log("WARN", "test warning")
        content = log.log_path.read_text()
        assert "[WARN]" in content
        assert "[WARNING]" not in content

    def test_fatal_format_not_critical(self, tmp_path: Path):
        """Формат [FATAL] а не [CRITICAL]."""
        log = Logger(tmp_path / "test.log")
        log.log("FATAL", "test fatal")
        content = log.log_path.read_text()
        assert "[FATAL]" in content
        assert "[CRITICAL]" not in content

    def test_custom_levels_written(self, tmp_path: Path):
        """Custom levels ENV/CHECK/WAIT попадают в файл."""
        log = Logger(tmp_path / "test.log")
        log.log("ENV", "env snapshot")
        log.log("CHECK", "health check")
        log.log("WAIT", "waiting")
        content = log.log_path.read_text()
        assert "[ENV]" in content
        assert "[CHECK]" in content
        assert "[WAIT]" in content
