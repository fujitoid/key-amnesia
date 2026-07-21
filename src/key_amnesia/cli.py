"""CLI entry point for key-amnesia / ka."""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path
from typing import Any

from key_amnesia import __version__
from key_amnesia.audit import audit_event
from key_amnesia.config import ConfigError, load_config, set_config_value
from key_amnesia.paths import vault_path
from key_amnesia.prompt_route import PromptRequest, require_human_auth
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

    # internal helpers (still support --help; omitted from epilog summary)
    sub.add_parser("_prompt-helper", help=argparse.SUPPRESS)
    sub.add_parser("_guard", help=argparse.SUPPRESS)

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


def _ensure_vault_password_for_new(password: str) -> None:
    vp = vault_path()
    if not vp.exists():
        save_vault(vp, password, empty_payload())


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
    # Prefer not putting secret values on argv — if omitted, prompt (inline only)
    request = PromptRequest(
        action="set",
        secret_names=[name],
        detail=json.dumps({"name": name, "value": value}) if value is not None else "",
    )
    # If value missing and interactive, collect value after password inline.
    ok, password, outcome = _auth_password(request)
    if not ok:
        print(f"Denied: {outcome.reason}", file=sys.stderr)
        return 1

    if password is not None:
        # Inline path: perform mutation here.
        if value is None:
            value = getpass.getpass(f"Value for '{name}': ")
        try:
            _ensure_vault_password_for_new(password)
            payload = load_vault(None, password)
        except VaultError as e:
            # New vault case already handled; wrong password:
            print(f"Error: {e}", file=sys.stderr)
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
        print(f"Set secret '{name}'.")
        return 0

    # Spawned helper already mutated (or failed).
    if outcome.status_only and outcome.status_only.get("action") == "set":
        print(f"Set secret '{name}'.")
        return 0
    # If value was None and we went non-interactive without detail, fail.
    if value is None:
        print(
            "Non-interactive set requires the value (or an interactive terminal).",
            file=sys.stderr,
        )
        return 1
    print(f"Denied: {outcome.reason or 'set failed'}", file=sys.stderr)
    return 1


def cmd_remove(args: argparse.Namespace) -> int:
    name = args.name
    request = PromptRequest(action="remove", secret_names=[name])
    ok, password, outcome = _auth_password(request)
    if not ok:
        print(f"Denied: {outcome.reason}", file=sys.stderr)
        return 1

    if password is not None:
        try:
            payload = load_vault(None, password)
        except VaultError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1
        if name not in payload["secrets"]:
            print(f"Unknown secret: {name}", file=sys.stderr)
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
        print(f"Removed secret '{name}'.")
        return 0

    if outcome.status_only and outcome.status_only.get("action") == "remove":
        print(f"Removed secret '{name}'.")
        return 0
    print(f"Denied: {outcome.reason or 'remove failed'}", file=sys.stderr)
    return 1


def cmd_run(args: argparse.Namespace) -> int:
    cmd = list(args.cmd or [])
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        print("Usage: key-amnesia run --secret NAME [--as NAME=ENV] -- command...", file=sys.stderr)
        return 2

    inject_as = _parse_as_mappings(args.as_env)
    secret_names = list(args.secret or [])
    # Also include names only referenced in --as
    for n in inject_as:
        if n not in secret_names:
            secret_names.append(n)
    if not secret_names:
        print("At least one --secret or --as is required.", file=sys.stderr)
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
            },
            timeout=3600,
        )
        if resp and resp.get("ok"):
            sys.stdout.write(resp.get("scrubbed_stdout", ""))
            sys.stderr.write(resp.get("scrubbed_stderr", ""))
            return int(resp.get("exit_code", 0))
        if resp and resp.get("expired"):
            print("Guard session expired; falling back to per-call auth.", file=sys.stderr)
        elif resp and not resp.get("ok"):
            # Guard reachable but denied (e.g. unknown secret) — don't fall through
            # with a password prompt unless it's expiry/connectivity.
            if "unknown" in str(resp.get("reason", "")):
                print(f"Error: {resp.get('reason')}", file=sys.stderr)
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
        print(f"Denied: {outcome.reason}", file=sys.stderr)
        return 1

    if password is not None:
        from key_amnesia.run_exec import run_with_secrets

        try:
            payload = load_vault(None, password)
        except VaultError as e:
            print(f"Error: {e}", file=sys.stderr)
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
            print(f"Unknown secrets: {', '.join(missing)}", file=sys.stderr)
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
    print(f"Denied: {outcome.reason or 'run failed'}", file=sys.stderr)
    return 1


def cmd_list(_args: argparse.Namespace) -> int:
    # Prefer live guard names if available; else sidecar (no prompt).
    from key_amnesia.guard import guard_is_alive, guard_request

    if guard_is_alive():
        resp = guard_request({"verb": "list"})
        if resp and resp.get("ok"):
            names = list(resp.get("names") or [])
            for n in names:
                print(n)
            return 0
    names = read_names()
    for n in names:
        print(n)
    return 0


def cmd_unlock(_args: argparse.Namespace) -> int:
    from key_amnesia.guard import guard_is_alive, start_guard_process

    if guard_is_alive():
        print("Guard session already active.", file=sys.stderr)
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
        print(f"Denied: {outcome.reason}", file=sys.stderr)
        return 1

    if password is not None:
        try:
            payload = load_vault(None, password)
        except VaultError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1
        try:
            pid = start_guard_process(payload, timeout_min)
        except Exception as e:  # noqa: BLE001
            print(f"Failed to start guard: {e}", file=sys.stderr)
            return 1
        audit_event("unlock", route=outcome.route, result="allowed")
        print(f"Unlocked (guard pid {pid}, timeout {timeout_min}m).")
        return 0

    if outcome.status_only and outcome.status_only.get("action") == "unlock":
        print(f"Unlocked (timeout {timeout_min}m).")
        return 0
    print(f"Denied: {outcome.reason or 'unlock failed'}", file=sys.stderr)
    return 1


def cmd_lock(_args: argparse.Namespace) -> int:
    from key_amnesia.guard import clear_guard_lock, guard_is_alive, guard_request

    if not guard_is_alive():
        clear_guard_lock()
        print("No active guard session.")
        return 0
    resp = guard_request({"verb": "lock"})
    clear_guard_lock()
    if resp and resp.get("ok"):
        print("Locked.")
        return 0
    print("Lock signal sent; cleared local lock file.")
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
        print(f"Denied: {outcome.reason}", file=sys.stderr)
        return 1

    if password is not None:
        try:
            payload = load_vault(None, password)
        except VaultError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1
        secrets_map = payload.get("secrets", {})
        if name not in secrets_map:
            print(f"Unknown secret: {name}", file=sys.stderr)
            return 1
        print(secrets_map[name])
        audit_event(
            "reveal", secret_names=[name], route=outcome.route, result="allowed"
        )
        return 0

    # Non-interactive: helper showed in its window; caller gets status only.
    if outcome.status_only and outcome.status_only.get("shown"):
        print(f"Secret '{name}' displayed in authentication console.")
        return 0
    print(f"Denied: {outcome.reason or 'reveal failed'}", file=sys.stderr)
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
        print(f"Denied: {outcome.reason}", file=sys.stderr)
        return 1

    if password is not None:
        from key_amnesia.clipboard import copy_to_clipboard

        try:
            payload = load_vault(None, password)
        except VaultError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1
        secrets_map = payload.get("secrets", {})
        if name not in secrets_map:
            print(f"Unknown secret: {name}", file=sys.stderr)
            return 1
        copy_to_clipboard(str(secrets_map[name]))
        audit_event(
            "copy", secret_names=[name], route=outcome.route, result="allowed"
        )
        print(f"Copied '{name}' to clipboard.")
        return 0

    if outcome.status_only and outcome.status_only.get("copied"):
        print(f"Secret '{name}' copied in authentication console.")
        return 0
    print(f"Denied: {outcome.reason or 'copy failed'}", file=sys.stderr)
    return 1


def cmd_config(args: argparse.Namespace) -> int:
    if args.config_command == "show" or args.config_command is None:
        cfg = load_config()
        print(json.dumps(cfg, indent=2))
        return 0
    if args.config_command == "set":
        request = PromptRequest(
            action="config",
            detail=json.dumps({"key": args.key, "value": args.value}),
        )
        ok, password, outcome = _auth_password(request)
        if not ok:
            print(f"Denied: {outcome.reason}", file=sys.stderr)
            return 1
        if password is not None:
            # Verify password against vault if it exists (fresh auth proof).
            vp = vault_path()
            if vp.exists():
                try:
                    load_vault(None, password)
                except VaultError as e:
                    print(f"Error: {e}", file=sys.stderr)
                    return 1
            try:
                set_config_value(args.key, args.value)
            except ConfigError as e:
                print(f"Error: {e}", file=sys.stderr)
                return 1
            audit_event(
                "config",
                route=outcome.route,
                result="allowed",
                reason=f"set {args.key}",
            )
            print(f"Set {args.key} = {args.value}")
            return 0
        if outcome.status_only and outcome.status_only.get("action") == "config":
            print(f"Set {args.key} = {args.value}")
            return 0
        print(f"Denied: {outcome.reason or 'config failed'}", file=sys.stderr)
        return 1
    print("Usage: key-amnesia config [show|set KEY VALUE]", file=sys.stderr)
    return 2


def cmd_status(_args: argparse.Namespace) -> int:
    from key_amnesia.guard import guard_is_alive, guard_request, read_guard_lock

    lock = read_guard_lock()
    if not lock or not guard_is_alive(lock):
        print("guard: inactive")
        cfg = load_config()
        print(f"session-mode: {cfg.get('session-mode')}")
        return 0
    resp = guard_request({"verb": "status"})
    print("guard: active")
    if resp and resp.get("ok"):
        print(f"pid: {resp.get('pid')}")
        print(f"expires_at: {resp.get('expires_at')}")
        print(f"secret_count: {resp.get('secret_count')}")
    else:
        print(f"pid: {lock.get('pid')}")
        print(f"expires_at: {lock.get('expires_at')}")
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
    if args.command == "_guard":
        from key_amnesia.guard import run_guard_main

        return run_guard_main()

    handlers = {
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
