"""Login CLI — manage URL/username ↔ secret associations (browser fill)."""

from __future__ import annotations

import argparse
from typing import Any

from key_amnesia import theme
from key_amnesia.audit import audit_event
from key_amnesia.logins import LoginError, add_login, list_logins, remove_login
from key_amnesia.paths import vault_path
from key_amnesia.prompt_route import AuthOutcome, PromptRequest, require_human_auth
from key_amnesia.vault import VaultError


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


def _auth(request: PromptRequest) -> tuple[bool, str | None, AuthOutcome]:
    outcome = require_human_auth(request)
    if not outcome.ok:
        return False, None, outcome
    return True, outcome.password, outcome


def _cmd_add(args: argparse.Namespace) -> int:
    url = args.url
    username = args.username
    secret_name = args.secret_name
    if not vault_path().exists():
        theme.error("Vault not initialized. Run 'ka init' first.")
        return 1

    request = PromptRequest(
        action="login-add",
        secret_names=[secret_name],
        detail=f"{username} @ {url} → {secret_name}",
    )
    ok, password, outcome = _auth(request)
    if not ok:
        theme.error(f"Denied: {outcome.reason}")
        return 1

    if password is not None:
        try:
            add_login(None, password, url, username, secret_name)
        except (LoginError, VaultError) as e:
            theme.error(f"Error: {e}")
            audit_event(
                "login-add",
                secret_names=[secret_name],
                route=outcome.route,
                result="denied",
                reason=str(e),
            )
            return 1
        audit_event(
            "login-add",
            secret_names=[secret_name],
            route=outcome.route,
            result="allowed",
        )
        theme.success(f"Added login {username} @ {url} → {secret_name}.")
        return 0

    if outcome.status_only and outcome.status_only.get("action") == "login-add":
        theme.success(f"Added login {username} @ {url} → {secret_name}.")
        return 0
    theme.error(f"Denied: {outcome.reason or 'login-add failed'}")
    return 1


def _cmd_list(args: argparse.Namespace) -> int:
    if not vault_path().exists():
        theme.error("Vault not initialized. Run 'ka init' first.")
        return 1

    request = PromptRequest(action="login-list")
    ok, password, outcome = _auth(request)
    if not ok:
        theme.error(f"Denied: {outcome.reason}")
        return 1

    if password is not None:
        try:
            entries = list_logins(None, password)
        except VaultError as e:
            theme.error(f"Error: {e}")
            audit_event(
                "login-list",
                route=outcome.route,
                result="denied",
                reason=str(e),
            )
            return 1
        audit_event(
            "login-list",
            route=outcome.route,
            result="allowed",
        )
        if not entries:
            theme.info("No login associations.")
            return 0
        for entry in entries:
            theme.out(
                f"{entry['url']}\t{entry['username']}\t{entry['secret_name']}"
            )
        return 0

    if outcome.status_only and outcome.status_only.get("action") == "login-list":
        # Spawned helper already displayed the list.
        return 0
    theme.error(f"Denied: {outcome.reason or 'login-list failed'}")
    return 1


def _cmd_remove(args: argparse.Namespace) -> int:
    url = args.url
    username = args.username
    if not vault_path().exists():
        theme.error("Vault not initialized. Run 'ka init' first.")
        return 1

    request = PromptRequest(
        action="login-remove",
        detail=f"{username} @ {url}",
    )
    ok, password, outcome = _auth(request)
    if not ok:
        theme.error(f"Denied: {outcome.reason}")
        return 1

    if password is not None:
        try:
            remove_login(None, password, url, username)
        except (LoginError, VaultError) as e:
            theme.error(f"Error: {e}")
            audit_event(
                "login-remove",
                route=outcome.route,
                result="denied",
                reason=str(e),
            )
            return 1
        audit_event(
            "login-remove",
            route=outcome.route,
            result="allowed",
        )
        theme.success(f"Removed login {username} @ {url}.")
        return 0

    if outcome.status_only and outcome.status_only.get("action") == "login-remove":
        theme.success(f"Removed login {username} @ {url}.")
        return 0
    theme.error(f"Denied: {outcome.reason or 'login-remove failed'}")
    return 1


def main(args: argparse.Namespace) -> int:
    cmd = getattr(args, "login_command", None)
    if cmd == "add":
        return _cmd_add(args)
    if cmd == "list":
        return _cmd_list(args)
    if cmd == "remove":
        return _cmd_remove(args)
    theme.error("Usage: key-amnesia login {add|list|remove} ...")
    return 2
