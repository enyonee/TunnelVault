"""IPsec/IKEv2 tunnel connection via strongSwan (swanctl)."""

from __future__ import annotations

from tv import proc, ui
from tv.app_config import cfg
from tv.i18n import t
from tv.vpn.base import ConfigParam, TunnelPlugin, VPNResult
from tv.vpn.registry import register


@register("ipsec")
class IPsecPlugin(TunnelPlugin):
    """IPsec/IKEv2 tunnel plugin (strongSwan swanctl)."""

    binary = "swanctl"
    type_display_name = "IPsec"
    process_names = ("charon", "charon-systemd")
    version_cmd = ("swanctl", "--version")

    @classmethod
    def emergency_patterns(cls, script_dir) -> list[str]:
        return ["charon"]

    @classmethod
    def discover_pid(cls, tcfg, script_dir) -> int | None:
        for name in cls.process_names:
            pids = proc.find_pids(name)
            if pids:
                return pids[0]
        return None

    @classmethod
    def config_schema(cls) -> list[ConfigParam]:
        return [
            ConfigParam(
                "config_file",
                "param.ipsec_config",
                default=cfg.defaults.ipsec_config,
                env_var="VPN_IPSEC_CONFIG",
                target="config_file",
            ),
            ConfigParam(
                "connection",
                "param.ipsec_connection",
                default=cfg.defaults.ipsec_connection,
                env_var="VPN_IPSEC_CONNECTION",
                target="extra",
            ),
        ]

    @property
    def process_name(self) -> str:
        return "charon"

    @property
    def display_name(self) -> str:
        return "IPsec"

    def connect(self) -> VPNResult:
        config_path = self.script_dir / self.cfg.config_file
        connection = self.cfg.extra.get("connection", cfg.defaults.ipsec_connection)

        self.log.log("INFO", f"Config: {config_path}")
        self.log.log("INFO", f"Connection: {connection}")

        # Load all configs (connections, secrets, pools, authorities)
        self.log.log("INFO", f"Launch: swanctl --load-all --file {config_path}")
        load_result = proc.run(
            ["swanctl", "--load-all", "--file", str(config_path)],
            sudo=True,
        )

        if load_result.returncode != 0:
            ui.fail(t("vpn.ipsec.setup_failed", rc=load_result.returncode))
            self.log.log(
                "ERROR",
                f"swanctl --load-all failed (exit code {load_result.returncode})",
            )
            stderr = (load_result.stderr or "").strip()
            details: list[tuple[str, str]] = []
            if stderr:
                details.append(("", stderr.splitlines()[-1]))
                self.log.log("ERROR", f"swanctl stderr: {stderr}")
            details.append(("", t("vpn.ipsec.log_hint", path=config_path)))
            ui.error_tree(details)
            return VPNResult(ok=False)

        # Initiate the child SA
        self.log.log("INFO", f"Launch: swanctl --initiate --child {connection}")
        init_result = proc.run(
            ["swanctl", "--initiate", "--child", connection],
            sudo=True,
        )

        if init_result.returncode != 0:
            ui.fail(t("vpn.ipsec.setup_failed", rc=init_result.returncode))
            self.log.log(
                "ERROR",
                f"swanctl --initiate failed (exit code {init_result.returncode})",
            )
            stderr = (init_result.stderr or "").strip()
            details = []
            if stderr:
                details.append(("", stderr.splitlines()[-1]))
                self.log.log("ERROR", f"swanctl stderr: {stderr}")
            details.append(("", t("vpn.ipsec.log_hint", path=config_path)))
            ui.error_tree(details)
            return VPNResult(ok=False)

        # Verify SA is established
        def _check_sa():
            r = proc.run(["swanctl", "--list-sas"], sudo=True)
            return connection in (r.stdout or "")

        if not proc.wait_for(
            f"IPsec SA ({connection})",
            _check_sa,
            cfg.timeouts.ipsec_sa,
            self.log,
        ):
            ui.fail(t("vpn.ipsec.not_connected", timeout=cfg.timeouts.ipsec_sa))
            self.log.log("ERROR", f"IPsec SA '{connection}' not established")
            return VPNResult(ok=False)

        # Find charon PID
        pid = None
        for name in self.process_names:
            pids = proc.find_pids(name)
            if pids:
                pid = pids[0]
                break
        self._pid = pid

        ui.ok(t("vpn.ipsec.connected", connection=connection))
        self.log.log("INFO", f"IPsec connected ({connection})")

        self.add_routes()
        self.setup_dns()

        return VPNResult(ok=True, pid=pid)

    def disconnect(self) -> None:
        """Override: use swanctl --terminate instead of kill by PID."""
        connection = self.cfg.extra.get("connection", cfg.defaults.ipsec_connection)
        self.log.log("INFO", f"Disconnect: swanctl --terminate --ike {connection}")
        proc.run(
            ["swanctl", "--terminate", "--ike", connection],
            sudo=True,
        )

    def _kill_by_pattern(self) -> None:
        proc.kill_pattern("charon", sudo=True)
