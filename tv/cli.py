"""CLI argument parsing for tunnelvault."""

from __future__ import annotations

import argparse

from tv.i18n import t


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=t("cli.desc"),
    )
    p.add_argument("--disconnect", action="store_true", help=t("cli.disconnect"))
    p.add_argument("--reconnect", action="store_true", help=t("cli.reconnect"))
    p.add_argument("--clear", action="store_true", help=t("cli.clear"))
    p.add_argument("--setup", action="store_true", help=t("cli.setup"))
    proxy_group = p.add_mutually_exclusive_group()
    proxy_group.add_argument(
        "--proxy",
        nargs="?",
        const=0,
        default=None,
        type=int,
        help=t("cli.proxy"),
    )
    proxy_group.add_argument(
        "--proxy-only",
        nargs="?",
        const=0,
        default=None,
        type=int,
        help=t("cli.proxy_only"),
    )
    p.add_argument("--debug", action="store_true", help=t("cli.debug"))
    p.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARN", "ERROR", "FATAL"],
        default=None,
        help=t("cli.log_level"),
    )
    p.add_argument("--status", action="store_true", help=t("cli.status"))
    p.add_argument("--check", action="store_true", help=t("cli.check"))
    p.add_argument("--reset", action="store_true", help=t("cli.reset"))
    p.add_argument("--validate", action="store_true", help=t("cli.validate"))
    p.add_argument("--only", type=str, default=None, help=t("cli.only"))
    p.add_argument("--logs", nargs="?", const="", default=None, help=t("cli.logs"))
    p.add_argument("--watch", action="store_true", help=t("cli.watch"))
    p.add_argument("--all", action="store_true", help=t("cli.all"))
    run_mode = p.add_mutually_exclusive_group()
    run_mode.add_argument("--no-daemon", action="store_true", help=t("cli.no_daemon"))
    run_mode.add_argument("--foreground", action="store_true", help=t("cli.foreground"))
    autostart = p.add_mutually_exclusive_group()
    autostart.add_argument("--enable", action="store_true", help=t("cli.enable"))
    autostart.add_argument("--disable", action="store_true", help=t("cli.disable"))
    return p.parse_args()
