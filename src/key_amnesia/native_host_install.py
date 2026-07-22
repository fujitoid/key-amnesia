"""Native Messaging host installer stubs — handlers filled by workstream B."""

from __future__ import annotations

import argparse
from typing import Any

from key_amnesia import theme


def build_browser_fill_parser(sub: Any) -> argparse.ArgumentParser:
    """Register `ka browser-fill` and its subcommands on the root subparsers."""
    p = sub.add_parser(
        "browser-fill",
        help="Install or inspect KeePassXC-Browser Native Messaging host",
    )
    bf_sub = p.add_subparsers(dest="browser_fill_command")
    bf_sub.add_parser("install", help="Install native messaging manifests")
    bf_sub.add_parser("status", help="Show per-browser install status")
    bf_sub.add_parser("uninstall", help="Remove key-amnesia native messaging manifests")
    return p


def main(args: argparse.Namespace) -> int:
    """Phase 0 stub — real handlers land in WS-B."""
    theme.error(
        "ka browser-fill is not implemented yet (Phase 0 stub; see workstream B).",
    )
    return 1
