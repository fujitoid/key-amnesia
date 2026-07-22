"""Login CLI stubs — handlers filled by workstream C."""

from __future__ import annotations

import argparse
from typing import Any

from key_amnesia import theme


def build_login_parser(sub: Any) -> argparse.ArgumentParser:
    """Register `ka login` and its subcommands on the root subparsers."""
    p = sub.add_parser(
        "login",
        help="Manage URL/username ↔ secret associations (browser fill)",
    )
    login_sub = p.add_subparsers(dest="login_command")
    p_add = login_sub.add_parser("add", help="Add a login association")
    p_add.add_argument("url")
    p_add.add_argument("username")
    p_add.add_argument("secret_name")
    login_sub.add_parser("list", help="List login associations")
    p_rm = login_sub.add_parser("remove", help="Remove a login association")
    p_rm.add_argument("url")
    p_rm.add_argument("username")
    return p


def main(args: argparse.Namespace) -> int:
    """Phase 0 stub — real handlers land in WS-C."""
    theme.error(
        "ka login is not implemented yet (Phase 0 stub; see workstream C).",
    )
    return 1
