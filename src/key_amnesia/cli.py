"""CLI entry point for key-amnesia / ka."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from pathlib import Path
from typing import Any

from key_amnesia import __version__
from key_amnesia import crypto
from key_amnesia.audit import audit_event
from key_amnesia.config import ConfigError, load_config, set_config_value
from key_amnesia.paths import vault_path
from key_amnesia.prompt_route import PromptRequest, require_human_auth
from key_amnesia import theme
from key_amnesia.vault import (
    VaultError,
    empty_payload,
    load_vault,
    read_names,
    save_vault,
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="key-amnesia",
        description=(
            "Encrypted secret vault with human-prompt routing and output scrubbing."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command")

    # init
    sub.add_parser(
        "init",
        help="Create an empty vault (double-confirm master password)",
    )

    # passwd / change-password
    sub.add_parser(
        "passwd",
        aliases=["change-password"],
        help="Change the master password (re-encrypts the vault with a fresh salt)",
    )

    # set
    p_set = sub.add_parser("set", help="Store or update a secret (always fresh auth)")
    p_set.add_argument("name", help="Secret name")
    p_set.add_argument(
        "value",
        nargs="?",
        default=None,
        help="Secret value (prompted if omitted; never prefer argv for secrets)",
    )

    # remove
    p_rm = sub.add_parser("remove", help="Remove a secret (always fresh auth)")
    p_rm.add_argument("name", help="Secret name")

    # run
    p_run = sub.add_parser(
        "run",
        help="Run a command with secrets injected into the environment",
    )
    p_run.add_argument(
        "--secret",
        action="append",
        default=[],
        metavar="NAME",
        help="Secret name to inject (repeatable)",
    )
    p_run.add_argument(
        "--as",
        dest="as_env",
        action="append",
        default=[],
        metavar="NAME=ENVVAR",
        help="Map secret NAME to environment variable ENVVAR",
    )
    p_run.add_argument(
        "cmd",
        nargs=argparse.REMAINDER,
        help="Command to run (use -- before command)",
    )

    # list
    sub.add_parser("list", help="List secret names (no prompt; names sidecar)")

    # unlock / lock
    sub.add_parser("unlock", help="Start cached guard session (requires password)")
    sub.add_parser("lock", help="Tear down cached guard session")

    # reveal / copy
    p_rev = sub.add_parser("reveal", help="Reveal a secret (always fresh auth)")
    p_rev.add_argument("name", help="Secret name")
    p_copy = sub.add_parser("copy", help="Copy a secret to clipboard (always fresh auth)")
    p_copy.add_argument("name", help="Secret name")

    # config
    p_cfg = sub.add_parser("config", help="View or set configuration")
    cfg_sub = p_cfg.add_subparsers(dest="config_command")
    cfg_sub.add_parser("show", help="Show current configuration")
    p_cfg_set = cfg_sub.add_parser(
        "set", help="Set a config value (always fresh auth)"
    )
    p_cfg_set.add_argument(
        "key",
        choices=["session-mode", "session-timeout-minutes", "prompt-timeout-seconds"],
    )
    p_cfg_set.add_argument("value")

    # status
    sub.add_parser("status", help="Show guard session status")

    # internal helper (still supports --help; omitted from epilog summary)
    sub.add_parser("_prompt-helper", help=argparse.SUPPRESS)

    return parser


def _parse_as_mappings(as_env: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for item in as_env:
        if "=" not in item:
            raise SystemExit(f"Invalid --as mapping (expected NAME=ENVVAR): {item}")
        name, envvar = item.split("=", 1)
        if not name or not envvar:
            raise SystemExit(f"Invalid --as mapping: {item}")
        out[name] = envvar
    return out


def _prompt_new_master_password() -> str | None:
    """Prompt twice for a new master password; return it or None on failure."""
    p1 = getpass.getpass("Master password: ")
    p2 = getpass.getpass("Confirm master password: ")
    if not p1:
        theme.error("Error: master password cannot be empty.")
        return None
    if p1 != p2:
        theme.error(
            "Error: passwords do not match — vault not created.",
        )
        return None
    return p1


def cmd_init(_args: argparse.Namespace) -> int:
    vp = vault_path()
    if vp.exists():
        theme.error(
            "vault already initialized, use ka set to add secrets",
        )
        return 1
    if not sys.stdin.isatty():
        theme.error(
            "Error: ka init requires an interactive terminal "
            "(run it directly in your console).",
        )
        return 1
    password = _prompt_new_master_password()
    if password is None:
        return 1
    try:
        save_vault(vp, password, empty_payload())
    except VaultError as e:
        theme.error(f"Error: {e}")
        return 1
    theme.success(f"Vault initialized at {vp}")
    theme.info(
        "Remember your master password — it cannot be recovered if forgotten."
    )
    return 0


def _auth_password(request: PromptRequest) -> tuple[bool, str | None, Any]:
    """Require human auth; return (ok, password_or_None, outcome).

    For inline: password is available.
    For spawned-console: password is None; outcome may carry run_result/status_only.
    """
    outcome = require_human_auth(request)
    if not outcome.ok:
        return False, None, outcome
    return True, outcome.password, outcome


def cmd_set(args: argparse.Namespace) -> int:
    name = args.name
    value = args.value
    if not vault_path().exists():
        theme.error(
            "Vault not initialized. Run 'ka init' first.",
        )
        return 1
    # Prefer not putting secret values on argv — if omitted, prompt (inline only)
    request = PromptRequest(
        action="set",
        secret_names=[name],
        detail=json.dumps({"name": name, "value": value}) if value is not None else "",
    )
    # If value missing and interactive, collect value after password inline.
    ok, password, outcome = _auth_password(request)
    if not ok:
        theme.error(f"Denied: {outcome.reason}")
        return 1

    if password is not None:
        # Inline path: perform mutation here.
        if value is None:
            value = getpass.getpass(f"Value for '{name}': ")
        try:
            payload = load_vault(None, password)
        except VaultError as e:
            theme.error(f"Error: {e}")
            audit_event(
                "set",
                secret_names=[name],
                route=outcome.route,
                result="denied",
                reason=str(e),
            )
            return 1
        payload["secrets"][name] = value
        save_vault(None, password, payload)
        audit_event(
            "set",
            secret_names=[name],
            route=outcome.route,
            result="allowed",
        )
        theme.success(f"Set secret '{name}'.")
        return 0

    # Spawned helper already mutated (or failed).
    if outcome.status_only and outcome.status_only.get("action") == "set":
        theme.success(f"Set secret '{name}'.")
        return 0
    # If value was None and we went non-interactive without detail, fail.
    if value is None:
        theme.error(
            "Non-interactive set requires the value (or an interactive terminal).",
        )
        return 1
    theme.error(f"Denied: {outcome.reason or 'set failed'}")
    return 1


def cmd_remove(args: argparse.Namespace) -> int:
    name = args.name
    request = PromptRequest(action="remove", secret_names=[name])
    ok, password, outcome = _auth_password(request)
    if not ok:
        theme.error(f"Denied: {outcome.reason}")
        return 1

    if password is not None:
        try:
            payload = load_vault(None, password)
        except VaultError as e:
            theme.error(f"Error: {e}")
            return 1
        if name not in payload["secrets"]:
            theme.error(f"Unknown secret: {name}")
            audit_event(
                "remove",
                secret_names=[name],
                route=outcome.route,
                result="denied",
                reason="unknown secret",
            )
            return 1
        del payload["secrets"][name]
        save_vault(None, password, payload)
        audit_event(
            "remove", secret_names=[name], route=outcome.route, result="allowed"
        )
        theme.success(f"Removed secret '{name}'.")
        return 0

    if outcome.status_only and outcome.status_only.get("action") == "remove":
        theme.success(f"Removed secret '{name}'.")
        return 0
    theme.error(f"Denied: {outcome.reason or 'remove failed'}")
    return 1


def cmd_run(args: argparse.Namespace) -> int:
    cmd = list(args.cmd or [])
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        theme.error("Usage: key-amnesia run --secret NAME [--as NAME=ENV] -- command...")
        return 2

    inject_as = _parse_as_mappings(args.as_env)
    secret_names = list(args.secret or [])
    # Also include names only referenced in --as
    for n in inject_as:
        if n not in secret_names:
            secret_names.append(n)
    if not secret_names:
        theme.error("At least one --secret or --as is required.")
        return 2

    # Try live guard first (cached mode).
    from key_amnesia.guard import guard_is_alive, guard_request

    if guard_is_alive():
        resp = guard_request(
            {
                "verb": "run",
                "secret_names": secret_names,
                "inject_as": inject_as,
                "command": cmd,
                "cwd": os.getcwd(),
            },
            timeout=3600,
        )
        if resp and resp.get("ok"):
            sys.stdout.write(resp.get("scrubbed_stdout", ""))
            sys.stderr.write(resp.get("scrubbed_stderr", ""))
            return int(resp.get("exit_code", 0))
        if resp and resp.get("expired"):
            theme.warn("Guard session expired; falling back to per-call auth.")
        elif resp and not resp.get("ok"):
            # Guard reachable but denied (e.g. unknown secret) — don't fall through
            # with a password prompt unless it's expiry/connectivity.
            if "unknown" in str(resp.get("reason", "")):
                theme.error(f"Error: {resp.get('reason')}")
                return 1

    request = PromptRequest(
        action="run",
        secret_names=secret_names,
        command=cmd,
        inject_as=inject_as,
        vault_path=str(vault_path()),
    )
    ok, password, outcome = _auth_password(request)
    if not ok:
        theme.error(f"Denied: {outcome.reason}")
        return 1

    if password is not None:
        from key_amnesia.run_exec import run_with_secrets

        try:
            payload = load_vault(None, password)
        except VaultError as e:
            theme.error(f"Error: {e}")
            audit_event(
                "run",
                secret_names=secret_names,
                command=cmd,
                route=outcome.route,
                result="denied",
                reason=str(e),
            )
            return 1
        secrets_map = {k: str(v) for k, v in payload["secrets"].items()}
        missing = [n for n in secret_names if n not in secrets_map]
        if missing:
            theme.error(f"Unknown secrets: {', '.join(missing)}")
            return 1
        env_inject = {inject_as.get(n, n): secrets_map[n] for n in secret_names}
        by_name = {n: secrets_map[n] for n in secret_names}
        result = run_with_secrets(cmd, env_inject, by_name)
        audit_event(
            "run",
            secret_names=secret_names,
            command=cmd,
            route=outcome.route,
            result="allowed",
        )
        sys.stdout.write(result.scrubbed_stdout)
        sys.stderr.write(result.scrubbed_stderr)
        return result.exit_code

    # Helper already executed.
    if outcome.run_result:
        sys.stdout.write(outcome.run_result.get("scrubbed_stdout", ""))
        sys.stderr.write(outcome.run_result.get("scrubbed_stderr", ""))
        return int(outcome.run_result.get("exit_code") or 0)
    theme.error(f"Denied: {outcome.reason or 'run failed'}")
    return 1


def cmd_list(_args: argparse.Namespace) -> int:
    # Prefer live guard names if available; else sidecar (no prompt).
    from key_amnesia.guard import guard_is_alive, guard_request

    if guard_is_alive():
        resp = guard_request({"verb": "list"})
        if resp and resp.get("ok"):
            names = list(resp.get("names") or [])
            for n in names:
                theme.out(n)
            return 0
    names = read_names()
    for n in names:
        theme.out(n)
    return 0


def cmd_unlock(_args: argparse.Namespace) -> int:
    """`ka unlock` *is* the guard: it decrypts, then blocks in this terminal.

    No detached child process, no bootstrap-env handoff. A non-interactive
    caller (agent-invoked) is routed the usual way — inline vs. spawned
    console — but a spawned helper console refuses the unlock action itself
    (a separate console can't become this terminal's foreground guard).
    """
    from key_amnesia.guard import guard_is_alive, run_foreground_guard

    if guard_is_alive():
        theme.warn("Guard session already active.")
        return 0

    cfg = load_config()
    timeout_min = int(cfg.get("session-timeout-minutes", 30))
    request = PromptRequest(
        action="unlock",
        detail=json.dumps({"session-timeout-minutes": timeout_min}),
        vault_path=str(vault_path()),
    )
    ok, password, outcome = _auth_password(request)
    if not ok:
        theme.error(f"Denied: {outcome.reason}")
        return 1

    if password is not None:
        try:
            payload = load_vault(None, password)
        except VaultError as e:
            theme.error(f"Error: {e}")
            audit_event(
                "unlock", route=outcome.route, result="denied", reason=str(e)
            )
            return 1
        audit_event("unlock", route=outcome.route, result="allowed")
        return run_foreground_guard(payload, timeout_min)

    theme.error(f"Denied: {outcome.reason or 'unlock failed'}")
    return 1


def cmd_lock(_args: argparse.Namespace) -> int:
    from key_amnesia.guard import (
        clear_admission_token,
        clear_guard_lock,
        format_no_guard_message,
        guard_is_alive,
        guard_request,
    )

    if not guard_is_alive():
        clear_guard_lock()
        clear_admission_token()
        theme.info(format_no_guard_message())
        return 0
    resp = guard_request({"verb": "lock"})
    clear_guard_lock()
    clear_admission_token()
    if resp and resp.get("ok"):
        theme.success("Locked.")
        return 0
    theme.info("Lock signal sent; cleared local lock file.")
    return 0


def cmd_reveal(args: argparse.Namespace) -> int:
    # Always fresh auth — never guard shortcut.
    name = args.name
    request = PromptRequest(
        action="reveal",
        secret_names=[name],
        vault_path=str(vault_path()),
    )
    ok, password, outcome = _auth_password(request)
    if not ok:
        theme.error(f"Denied: {outcome.reason}")
        return 1

    if password is not None:
        try:
            payload = load_vault(None, password)
        except VaultError as e:
            theme.error(f"Error: {e}")
            return 1
        secrets_map = payload.get("secrets", {})
        if name not in secrets_map:
            theme.error(f"Unknown secret: {name}")
            return 1
        # Raw secret value — never themed.
        sys.stdout.write(f"{secrets_map[name]}\n")
        audit_event(
            "reveal", secret_names=[name], route=outcome.route, result="allowed"
        )
        return 0

    # Non-interactive: helper showed in its window; caller gets status only.
    if outcome.status_only and outcome.status_only.get("shown"):
        theme.info(f"Secret '{name}' displayed in authentication console.")
        return 0
    theme.error(f"Denied: {outcome.reason or 'reveal failed'}")
    return 1


def cmd_copy(args: argparse.Namespace) -> int:
    name = args.name
    request = PromptRequest(
        action="copy",
        secret_names=[name],
        vault_path=str(vault_path()),
    )
    ok, password, outcome = _auth_password(request)
    if not ok:
        theme.error(f"Denied: {outcome.reason}")
        return 1

    if password is not None:
        from key_amnesia.clipboard import copy_to_clipboard

        try:
            payload = load_vault(None, password)
        except VaultError as e:
            theme.error(f"Error: {e}")
            return 1
        secrets_map = payload.get("secrets", {})
        if name not in secrets_map:
            theme.error(f"Unknown secret: {name}")
            return 1
        copy_to_clipboard(str(secrets_map[name]))
        audit_event(
            "copy", secret_names=[name], route=outcome.route, result="allowed"
        )
        theme.success(f"Copied '{name}' to clipboard.")
        return 0

    if outcome.status_only and outcome.status_only.get("copied"):
        theme.info(f"Secret '{name}' copied in authentication console.")
        return 0
    theme.error(f"Denied: {outcome.reason or 'copy failed'}")
    return 1


def cmd_config(args: argparse.Namespace) -> int:
    if args.config_command == "show" or args.config_command is None:
        cfg = load_config()
        theme.out(json.dumps(cfg, indent=2))
        return 0
    if args.config_command == "set":
        request = PromptRequest(
            action="config",
            detail=json.dumps({"key": args.key, "value": args.value}),
        )
        ok, password, outcome = _auth_password(request)
        if not ok:
            theme.error(f"Denied: {outcome.reason}")
            return 1
        if password is not None:
            # Verify password against vault if it exists (fresh auth proof).
            vp = vault_path()
            if vp.exists():
                try:
                    load_vault(None, password)
                except VaultError as e:
                    theme.error(f"Error: {e}")
                    return 1
            try:
                set_config_value(args.key, args.value)
            except ConfigError as e:
                theme.error(f"Error: {e}")
                return 1
            audit_event(
                "config",
                route=outcome.route,
                result="allowed",
                reason=f"set {args.key}",
            )
            theme.success(f"Set {args.key} = {args.value}")
            return 0
        if outcome.status_only and outcome.status_only.get("action") == "config":
            theme.success(f"Set {args.key} = {args.value}")
            return 0
        theme.error(f"Denied: {outcome.reason or 'config failed'}")
        return 1
    theme.error("Usage: key-amnesia config [show|set KEY VALUE]")
    return 2


def cmd_status(_args: argparse.Namespace) -> int:
    from key_amnesia.guard import (
        format_no_guard_message,
        guard_is_alive,
        guard_request,
        read_guard_lock,
    )

    lock = read_guard_lock()
    if not lock or not guard_is_alive(lock):
        theme.out("guard: inactive")
        theme.out(format_no_guard_message())
        cfg = load_config()
        theme.out(f"session-mode: {cfg.get('session-mode')}")
        return 0
    resp = guard_request({"verb": "status"})
    theme.out("guard: active")
    if resp and resp.get("ok"):
        theme.out(f"pid: {resp.get('pid')}")
        theme.out(f"expires_at: {resp.get('expires_at')}")
        theme.out(f"secret_count: {resp.get('secret_count')}")
        theme.out(f"admitted: {'yes' if resp.get('admitted') else 'no'}")
        if resp.get("admitted_since"):
            theme.out(f"admitted_since: {resp.get('admitted_since')}")
        theme.out(f"request_count: {resp.get('request_count', 0)}")
    else:
        theme.out(f"pid: {lock.get('pid')}")
        theme.out(f"expires_at: {lock.get('expires_at')}")
    return 0


def cmd_passwd(_args: argparse.Namespace) -> int:
    """Change the master password: re-encrypts the vault with a fresh salt.

    Refuses outright while a guard session is alive (the guard holds the
    old-password-derived key in memory and would go stale mid-session), and
    is TTY-only like `ka init` — never routed through the spawned-console
    helper, since the master password can never leave this process either
    way.
    """
    from key_amnesia.guard import guard_is_alive

    if guard_is_alive():
        theme.error("Lock the vault first: ka lock")
        return 1

    vp = vault_path()
    if not vp.exists():
        theme.error("Vault not initialized. Run 'ka init' first.")
        return 1
    if not sys.stdin.isatty():
        theme.error(
            "Error: ka passwd requires an interactive terminal "
            "(run it directly in your console)."
        )
        return 1

    current_password = getpass.getpass("Current master password: ")
    try:
        payload = load_vault(vp, current_password)
    except VaultError as e:
        theme.error(f"Error: {e}")
        audit_event("passwd", route="inline", result="denied", reason=str(e))
        return 1

    new_password = _prompt_new_master_password()
    if new_password is None:
        audit_event(
            "passwd", route="inline", result="denied", reason="new password rejected"
        )
        return 1

    save_vault(vp, new_password, payload, salt=crypto.generate_salt())
    audit_event("passwd", route="inline", result="allowed")
    theme.success("Master password changed.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    if args.command == "_prompt-helper":
        from key_amnesia.prompt_route import run_prompt_helper

        return run_prompt_helper()

    handlers = {
        "init": cmd_init,
        "passwd": cmd_passwd,
        "change-password": cmd_passwd,
        "set": cmd_set,
        "remove": cmd_remove,
        "run": cmd_run,
        "list": cmd_list,
        "unlock": cmd_unlock,
        "lock": cmd_lock,
        "reveal": cmd_reveal,
        "copy": cmd_copy,
        "config": cmd_config,
        "status": cmd_status,
    }
    handler = handlers.get(args.command)
    if handler is None:
        parser.print_help()
        return 2
    return handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
