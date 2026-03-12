"""Tests for tv.status module."""

from __future__ import annotations

from unittest.mock import patch, MagicMock

from tv import status


class TestShowProcesses:
    def test_finds_running_processes(self, capsys):
        with patch("tv.status.proc") as mock_proc:
            mock_proc.find_pids.side_effect = lambda p: [1234] if p == "openvpn" else []
            status._show_processes()

        out = capsys.readouterr().out
        assert "openvpn" in out
        assert "1234" in out

    def test_no_processes_found(self, capsys):
        with patch("tv.status.proc") as mock_proc:
            mock_proc.find_pids.return_value = []
            status._show_processes()

        out = capsys.readouterr().out
        assert "no running VPN" in out


class TestShowInterfaces:
    @patch("tv.status.IS_WINDOWS", False)
    def test_tunnel_interfaces(self, mock_net, capsys):
        mock_net.interfaces.return_value = {
            "en0": "192.168.1.5",
            "utun99": "10.0.0.2",
            "ppp0": "10.1.0.1",
            "lo0": "127.0.0.1",
        }
        status._show_interfaces(mock_net)
        out = capsys.readouterr().out
        assert "utun99" in out
        assert "ppp0" in out
        assert "en0" not in out  # not a tunnel interface

    @patch("tv.status.IS_WINDOWS", False)
    def test_no_tunnel_interfaces(self, mock_net, capsys):
        mock_net.interfaces.return_value = {"en0": "192.168.1.5"}
        status._show_interfaces(mock_net)
        out = capsys.readouterr().out
        assert "no tunnel interfaces" in out


class TestShowResolvers:
    @patch("tv.status.IS_WINDOWS", False)
    def test_resolver_files_found(self, tmp_path, capsys):
        resolver_dir = tmp_path / "resolver"
        resolver_dir.mkdir()
        (resolver_dir / "test.local").write_text("# tunnelvault\nnameserver 10.0.0.1\n")

        with patch("tv.status.cfg") as mock_cfg:
            mock_cfg.paths.resolver_dir = str(resolver_dir)
            status._show_resolvers()

        out = capsys.readouterr().out
        assert "test.local" in out
        assert "10.0.0.1" in out

    @patch("tv.status.IS_WINDOWS", False)
    def test_no_resolver_files(self, tmp_path, capsys):
        resolver_dir = tmp_path / "resolver"
        resolver_dir.mkdir()

        with patch("tv.status.cfg") as mock_cfg:
            mock_cfg.paths.resolver_dir = str(resolver_dir)
            status._show_resolvers()

        out = capsys.readouterr().out
        assert "no tunnelvault resolver" in out

    @patch("tv.status.IS_WINDOWS", False)
    def test_resolver_dir_missing(self, tmp_path, capsys):
        with patch("tv.status.cfg") as mock_cfg:
            mock_cfg.paths.resolver_dir = str(tmp_path / "nonexistent")
            status._show_resolvers()

        out = capsys.readouterr().out
        assert "does not exist" in out

    @patch("tv.status.IS_WINDOWS", False)
    def test_non_tunnelvault_files_ignored(self, tmp_path, capsys):
        resolver_dir = tmp_path / "resolver"
        resolver_dir.mkdir()
        (resolver_dir / "other.local").write_text("nameserver 8.8.8.8\n")

        with patch("tv.status.cfg") as mock_cfg:
            mock_cfg.paths.resolver_dir = str(resolver_dir)
            status._show_resolvers()

        out = capsys.readouterr().out
        assert "no tunnelvault resolver" in out


class TestShowGateway:
    def test_gateway_found(self, mock_net, capsys):
        mock_net.default_gateway.return_value = "192.168.1.1"
        status._show_gateway(mock_net)
        out = capsys.readouterr().out
        assert "192.168.1.1" in out

    def test_no_gateway(self, mock_net, capsys):
        mock_net.default_gateway.return_value = None
        status._show_gateway(mock_net)
        out = capsys.readouterr().out
        assert "not determined" in out


class TestShowExternalIp:
    def test_external_ip(self, capsys):
        with patch("tv.status.get_external_ip", return_value="1.2.3.4"):
            status._show_external_ip()
        out = capsys.readouterr().out
        assert "1.2.3.4" in out

    def test_no_external_ip(self, capsys):
        with patch("tv.status.get_external_ip", return_value=None):
            status._show_external_ip()
        out = capsys.readouterr().out
        assert "could not determine" in out


class TestRun:
    def test_full_run(self, mock_net, capsys):
        with (
            patch("tv.status.proc") as mock_proc,
            patch("tv.status.get_external_ip", return_value="5.5.5.5"),
        ):
            mock_proc.find_pids.return_value = []
            mock_net.interfaces.return_value = {"en0": "192.168.1.5"}
            status.run(net=mock_net)

        out = capsys.readouterr().out
        assert "status" in out

    def test_run_without_net(self, capsys):
        mock_net_instance = MagicMock()
        mock_net_instance.interfaces.return_value = {}
        mock_net_instance.default_gateway.return_value = None
        with (
            patch("tv.net.create", return_value=mock_net_instance),
            patch("tv.status.proc") as mock_proc,
            patch("tv.status.get_external_ip", return_value=None),
        ):
            mock_proc.find_pids.return_value = []
            status.run()

        out = capsys.readouterr().out
        assert "status" in out
