"""Human-auth prompt routing: inline getpass or CREATE_NEW_CONSOLE helper.

Nothing sensitive on argv — ever. Helper gets request/authkey/reply address
via environment variables on Popen env=.
"""

from __future__ import annotations

import getpass
import json
import os
import sys
import threading
import time
from dataclasses import asdict, dataclass, field
from multiprocessing.connection import Connection
from typing import Any, Callable

from key_amnesia import ipc
from key_amnesia import theme
from key_amnesia.audit import audit_event
from key_amnesia.config import load_config
from key_amnesia.platform import spawn_isolated_console

# Environment keys for helper handoff (never put these on argv).
ENV_REQUEST = "KEY_AMNESIA_PROMPT_REQUEST"
ENV_AUTHKEY = "KEY_AMNESIA_PROMPT_AUTHKEY"
ENV_ADDRESS = "KEY_AMNESIA_PROMPT_ADDRESS"
ENV_PARENT_PID = "KEY_AMNESIA_PROMPT_PARENT_PID"
ENV_TIMEOUT = "KEY_AMNESIA_PROMPT_TIMEOUT"


@dataclass
class PromptRequest:
    action: str
    secret_names: list[str] = field(default_factory=list)
    command: list[str] = field(default_factory=list)
    # For run: mapping secret_name -> env var name
    inject_as: dict[str, str] = field(default_factory=dict)
    # Extra context for helper (e.g. reveal target name)
    detail: str = ""
    # Vault path override for helper
    vault_path: str = ""


@dataclass
class AuthOutcome:
    ok: bool
    route: str  # inline | spawned-console
    reason: str = ""
    # Present only for inline successful auth where caller needs password locally.
    # For spawned-console run, helper executes; password is never returned.
    password: str | None = None
    # Helper-executed run results (scrubbed only)
    run_result: dict[str, Any] | None = None
    # Helper reveal/copy status
    status_only: dict[str, Any] | None = None


def _isatty() -> bool:
    try:
        return sys.stdin.isatty()
    except Exception:
        return False


def _prompt_password_inline(request: PromptRequest) -> str:
    theme.info(
        f"key-amnesia: authentication required for '{request.action}'",
        file=sys.stderr,
    )
    if request.secret_names:
        theme.info(f"  secrets: {', '.join(request.secret_names)}", file=sys.stderr)
    if request.detail:
        theme.info(f"  {request.detail}", file=sys.stderr)
    return getpass.getpass("Master password: ")


def _helper_command() -> list[str]:
    """Bare argv for the prompt helper — no secrets, no request JSON."""
    # Prefer installed console script; fall back to python -m for tests/dev.
    return [sys.executable, "-m", "key_amnesia", "_prompt-helper"]


def _spawn_helper(
    request: PromptRequest,
    address: str,
    authkey: bytes,
    timeout_s: int,
    *,
    popen_fn: Callable[..., Any] | None = None,
) -> Any:
    """Spawn helper with CREATE_NEW_CONSOLE; sensitive data only in env."""
    env = os.environ.copy()
    env[ENV_REQUEST] = json.dumps(asdict(request))
    env[ENV_AUTHKEY] = ipc.authkey_to_hex(authkey)
    env[ENV_ADDRESS] = address
    env[ENV_PARENT_PID] = str(os.getpid())
    env[ENV_TIMEOUT] = str(timeout_s)

    cmd = _helper_command()
    return spawn_isolated_console(cmd, env, popen_fn=popen_fn)


def _prompt_approve_inline(request: PromptRequest) -> bool:
    theme.info(
        "key-amnesia: browser fill approval required",
        file=sys.stderr,
    )
    try:
        detail = json.loads(request.detail) if request.detail else {}
    except json.JSONDecodeError:
        detail = {}
    url = str(detail.get("url") or request.detail or "")
    usernames = detail.get("usernames") or []
    secret_names = detail.get("secret_names") or request.secret_names
    if url:
        theme.info(f"  site: {url}", file=sys.stderr)
    if usernames:
        theme.info(f"  usernames: {', '.join(str(u) for u in usernames)}", file=sys.stderr)
    if secret_names:
        theme.info(
            f"  secret names: {', '.join(str(n) for n in secret_names)}",
            file=sys.stderr,
        )
    theme.info("  (passwords are never shown here)", file=sys.stderr)
    ans = input("Allow fill? [y/N] ").strip().lower()
    return ans in ("y", "yes")


def require_browser_fill_approval(
    request: PromptRequest,
    timeout_s: int | None = None,
    *,
    approve_provider: Callable[[], bool] | None = None,
    popen_fn: Callable[..., Any] | None = None,
    isatty_fn: Callable[[], bool] | None = None,
) -> AuthOutcome:
    """Yes/No approval for browser fill — never collects a master password.

    Used only when a live unlock/fill session already holds the vault.
    """
    if request.action != "browser-fill-approve":
        request = PromptRequest(
            action="browser-fill-approve",
            secret_names=request.secret_names,
            command=request.command,
            inject_as=request.inject_as,
            detail=request.detail,
            vault_path=request.vault_path,
        )

    cfg = load_config()
    if timeout_s is None:
        timeout_s = int(cfg.get("prompt-timeout-seconds", 90))

    tty = (isatty_fn or _isatty)()
    if tty:
        try:
            if approve_provider is not None:
                approved = bool(approve_provider())
            else:
                approved = _prompt_approve_inline(request)
        except (EOFError, KeyboardInterrupt):
            return AuthOutcome(
                ok=False,
                route="inline",
                reason="approval cancelled",
                status_only={"approved": False, "action": "browser-fill-approve"},
            )
        return AuthOutcome(
            ok=approved,
            route="inline",
            reason="" if approved else "denied",
            status_only={"approved": approved, "action": "browser-fill-approve"},
        )

    # Non-interactive: spawn helper console for yes/no only (no password).
    listener = None
    proc = None
    try:
        listener, address, authkey = ipc.start_listener()
        try:
            proc = _spawn_helper(
                request, address, authkey, timeout_s, popen_fn=popen_fn
            )
        except OSError as e:
            return AuthOutcome(ok=False, route="spawned-console", reason=str(e))

        deadline = time.monotonic() + timeout_s
        conn: Connection | None = None
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            accepted: list[Connection | BaseException] = []

            def _accept() -> None:
                try:
                    accepted.append(listener.accept())
                except BaseException as exc:  # noqa: BLE001
                    accepted.append(exc)

            t = threading.Thread(target=_accept, daemon=True)
            t.start()
            t.join(timeout=min(1.0, max(0.1, remaining)))
            if accepted:
                item = accepted[0]
                if isinstance(item, BaseException):
                    raise item
                conn = item
                break
            if proc.poll() is not None:
                break
        else:
            return AuthOutcome(
                ok=False, route="spawned-console", reason="approval timed out"
            )

        if conn is None:
            return AuthOutcome(
                ok=False,
                route="spawned-console",
                reason="helper exited without connecting",
            )

        try:
            remaining = max(0.1, deadline - time.monotonic())
            reply = ipc.recv_msg(conn, timeout=remaining)
        except TimeoutError:
            return AuthOutcome(
                ok=False, route="spawned-console", reason="helper reply timed out"
            )
        finally:
            try:
                conn.close()
            except Exception:
                pass

        if "password" in reply or "secret_value" in reply or "secrets" in reply:
            reply = {
                k: v
                for k, v in reply.items()
                if k not in ("password", "secret_value", "secrets")
            }

        so = reply.get("status_only") if isinstance(reply.get("status_only"), dict) else {}
        approved = bool(so.get("approved")) if "approved" in so else bool(reply.get("ok"))
        reason = str(reply.get("reason", ""))
        return AuthOutcome(
            ok=approved,
            route="spawned-console",
            reason=reason if not approved else "",
            status_only={
                "approved": approved,
                "action": "browser-fill-approve",
            },
        )
    finally:
        if listener is not None:
            try:
                listener.close()
            except Exception:
                pass
        if proc is not None and proc.poll() is None:
            try:
                proc.terminate()
            except Exception:
                pass


def require_human_auth(
    request: PromptRequest,
    timeout_s: int | None = None,
    *,
    password_provider: Callable[[], str] | None = None,
    popen_fn: Callable[..., Any] | None = None,
    isatty_fn: Callable[[], bool] | None = None,
) -> AuthOutcome:
    """Route to inline getpass or spawned console helper.

    Master password is never satisfiable non-interactively without a spawned
    console. Password never travels over IPC.
    """
    cfg = load_config()
    if timeout_s is None:
        timeout_s = int(cfg.get("prompt-timeout-seconds", 90))

    tty = (isatty_fn or _isatty)()
    if tty:
        try:
            if password_provider is not None:
                password = password_provider()
            else:
                password = _prompt_password_inline(request)
        except (EOFError, KeyboardInterrupt):
            audit_event(
                request.action,
                secret_names=request.secret_names,
                command=request.command or None,
                route="inline",
                result="denied",
                reason="prompt cancelled",
            )
            return AuthOutcome(ok=False, route="inline", reason="prompt cancelled")
        if not password:
            audit_event(
                request.action,
                secret_names=request.secret_names,
                command=request.command or None,
                route="inline",
                result="denied",
                reason="empty password",
            )
            return AuthOutcome(ok=False, route="inline", reason="empty password")
        return AuthOutcome(ok=True, route="inline", password=password)

    # Non-interactive: spawn helper console (Windows only).
    listener = None
    proc = None
    try:
        listener, address, authkey = ipc.start_listener()
        try:
            proc = _spawn_helper(
                request, address, authkey, timeout_s, popen_fn=popen_fn
            )
        except OSError as e:
            audit_event(
                request.action,
                secret_names=request.secret_names,
                command=request.command or None,
                route="spawned-console",
                result="denied",
                reason=str(e),
            )
            return AuthOutcome(ok=False, route="spawned-console", reason=str(e))

        # Wait for helper to connect and reply.
        deadline = time.monotonic() + timeout_s
        conn: Connection | None = None
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            # Listener.accept has no timeout on all platforms; use a thread.
            accepted: list[Connection | BaseException] = []

            def _accept() -> None:
                try:
                    accepted.append(listener.accept())
                except BaseException as exc:  # noqa: BLE001
                    accepted.append(exc)

            t = threading.Thread(target=_accept, daemon=True)
            t.start()
            t.join(timeout=min(1.0, max(0.1, remaining)))
            if accepted:
                item = accepted[0]
                if isinstance(item, BaseException):
                    raise item
                conn = item
                break
            if proc.poll() is not None:
                break
        else:
            audit_event(
                request.action,
                secret_names=request.secret_names,
                command=request.command or None,
                route="spawned-console",
                result="timeout",
                reason="prompt timed out",
            )
            return AuthOutcome(ok=False, route="spawned-console", reason="prompt timed out")

        if conn is None:
            audit_event(
                request.action,
                secret_names=request.secret_names,
                command=request.command or None,
                route="spawned-console",
                result="denied",
                reason="helper exited without connecting",
            )
            return AuthOutcome(
                ok=False,
                route="spawned-console",
                reason="helper exited without connecting",
            )

        try:
            remaining = max(0.1, deadline - time.monotonic())
            reply = ipc.recv_msg(conn, timeout=remaining)
        except TimeoutError:
            audit_event(
                request.action,
                secret_names=request.secret_names,
                command=request.command or None,
                route="spawned-console",
                result="timeout",
                reason="helper reply timed out",
            )
            return AuthOutcome(
                ok=False, route="spawned-console", reason="helper reply timed out"
            )
        finally:
            try:
                conn.close()
            except Exception:
                pass

        # Sanitize: never accept password / secret values from helper.
        if "password" in reply or "secret_value" in reply or "secrets" in reply:
            # Strip and treat as protocol violation — do not propagate.
            reply = {k: v for k, v in reply.items() if k not in ("password", "secret_value", "secrets")}

        ok = bool(reply.get("ok"))
        reason = str(reply.get("reason", ""))
        result = "allowed" if ok else ("timeout" if "timeout" in reason.lower() else "denied")
        audit_event(
            request.action,
            secret_names=request.secret_names,
            command=request.command or None,
            route="spawned-console",
            result=result,
            reason=reason,
        )
        outcome = AuthOutcome(ok=ok, route="spawned-console", reason=reason)
        if "run_result" in reply and isinstance(reply["run_result"], dict):
            # Scrubbed I/O + exit only — never raw secrets.
            rr = reply["run_result"]
            outcome.run_result = {
                "exit_code": rr.get("exit_code"),
                "scrubbed_stdout": rr.get("scrubbed_stdout", ""),
                "scrubbed_stderr": rr.get("scrubbed_stderr", ""),
            }
        if "status_only" in reply and isinstance(reply["status_only"], dict):
            outcome.status_only = {
                k: v
                for k, v in reply["status_only"].items()
                if k in ("shown", "copied", "action", "name", "approved", "key")
            }
        return outcome
    finally:
        if listener is not None:
            try:
                listener.close()
            except Exception:
                pass
        if proc is not None and proc.poll() is None:
            try:
                proc.terminate()
            except Exception:
                pass


def clear_helper_env() -> dict[str, str]:
    """Read and clear helper env vars from os.environ. Returns the values."""
    keys = [ENV_REQUEST, ENV_AUTHKEY, ENV_ADDRESS, ENV_PARENT_PID, ENV_TIMEOUT]
    out: dict[str, str] = {}
    for k in keys:
        if k in os.environ:
            out[k] = os.environ.pop(k)
    return out


def parent_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if sys.platform == "win32":
        import ctypes

        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        STILL_ACTIVE = 259
        handle = ctypes.windll.kernel32.OpenProcess(  # type: ignore[attr-defined]
            PROCESS_QUERY_LIMITED_INFORMATION, False, pid
        )
        if not handle:
            return False
        try:
            exit_code = ctypes.c_ulong()
            ok = ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code))  # type: ignore[attr-defined]
            if not ok:
                return False
            return exit_code.value == STILL_ACTIVE
        finally:
            ctypes.windll.kernel32.CloseHandle(handle)  # type: ignore[attr-defined]
    else:
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False


def run_prompt_helper() -> int:
    """Entry for `_prompt-helper`: read env, prompt, act, reply over IPC.

    Never puts password or raw secrets on the reply channel for reveal/copy
    beyond local console/clipboard. For run: executes locally and returns
    scrubbed I/O only.
    """
    from pathlib import Path

    from key_amnesia.clipboard import copy_to_clipboard
    from key_amnesia.run_exec import run_with_secrets
    from key_amnesia.vault import VaultError, load_vault

    env = clear_helper_env()
    try:
        request_raw = env[ENV_REQUEST]
        authkey = ipc.authkey_from_hex(env[ENV_AUTHKEY])
        address = env[ENV_ADDRESS]
        parent_pid = int(env.get(ENV_PARENT_PID, "0"))
        timeout_s = int(env.get(ENV_TIMEOUT, "90"))
    except (KeyError, ValueError) as e:
        theme.error(f"key-amnesia helper: missing/invalid env handoff: {e}")
        input("Press Enter to close...")
        return 1

    request_data = json.loads(request_raw)
    request = PromptRequest(**{
        k: request_data.get(k, v)
        for k, v in {
            "action": "",
            "secret_names": [],
            "command": [],
            "inject_as": {},
            "detail": "",
            "vault_path": "",
        }.items()
    })
    # Fix types from JSON
    request = PromptRequest(
        action=str(request_data.get("action", "")),
        secret_names=list(request_data.get("secret_names") or []),
        command=list(request_data.get("command") or []),
        inject_as=dict(request_data.get("inject_as") or {}),
        detail=str(request_data.get("detail") or ""),
        vault_path=str(request_data.get("vault_path") or ""),
    )

    if parent_pid and not parent_alive(parent_pid):
        theme.error("key-amnesia helper: parent process gone; cancelling.")
        return 1

    theme.info("=" * 50)
    theme.info("  key-amnesia — human authentication")
    theme.info("=" * 50)
    theme.out(f"Action : {request.action}")
    if request.secret_names:
        theme.out(f"Secrets: {', '.join(request.secret_names)}")
    if request.command:
        theme.out(f"Command: {' '.join(request.command)}")
    if request.detail:
        theme.out(request.detail)
    theme.out()

    # Watch parent in background
    cancel = {"flag": False}

    def _watch() -> None:
        while not cancel["flag"]:
            if parent_pid and not parent_alive(parent_pid):
                cancel["flag"] = True
                return
            time.sleep(0.5)

    watcher = threading.Thread(target=_watch, daemon=True)
    watcher.start()

    reply: dict[str, Any] = {"ok": False, "reason": ""}

    # Browser-fill approval: yes/no only — never collect a master password.
    if request.action == "browser-fill-approve":
        try:
            detail = json.loads(request.detail) if request.detail else {}
        except json.JSONDecodeError:
            detail = {}
        url = str(detail.get("url") or "")
        usernames = detail.get("usernames") or []
        secret_names = detail.get("secret_names") or request.secret_names
        theme.info("Browser fill approval (no password required)")
        if url:
            theme.out(f"Site     : {url}")
        if usernames:
            theme.out(f"Usernames: {', '.join(str(u) for u in usernames)}")
        if secret_names:
            theme.out(f"Secrets  : {', '.join(str(n) for n in secret_names)}")
        theme.out("(Password values are never shown.)")
        theme.out()
        try:
            ans = input("Allow fill? [y/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            ans = ""
        if cancel["flag"]:
            theme.error("Cancelled (parent exited).")
            return 1
        approved = ans in ("y", "yes")
        reply["ok"] = approved
        reply["reason"] = "" if approved else "denied"
        reply["status_only"] = {
            "approved": approved,
            "action": "browser-fill-approve",
        }
        try:
            if parent_pid and not parent_alive(parent_pid):
                theme.error("Parent gone; discarding reply.")
                return 1
            conn = ipc.connect(address, authkey)
            try:
                safe = {
                    k: v
                    for k, v in reply.items()
                    if k in ("ok", "reason", "run_result", "status_only")
                }
                ipc.send_msg(conn, safe)
            finally:
                conn.close()
        except Exception as e:  # noqa: BLE001
            theme.error(f"Failed to reply to parent: {e}")
            input("Press Enter to close...")
            return 1
        cancel["flag"] = True
        if approved:
            theme.success("Approved.")
        else:
            theme.out("Denied.")
        time.sleep(0.8)
        return 0 if approved else 1

    try:
        password = getpass.getpass("Master password: ")
    except (EOFError, KeyboardInterrupt):
        password = ""

    if cancel["flag"]:
        theme.error("Cancelled (parent exited).")
        return 1

    try:
        if not password:
            reply["reason"] = "empty password"
        else:
            vault = Path(request.vault_path) if request.vault_path else None
            try:
                payload = load_vault(vault, password)
            except VaultError as e:
                reply["reason"] = str(e)
                payload = None

            if payload is not None:
                secrets_map: dict[str, str] = {
                    k: str(v) for k, v in payload.get("secrets", {}).items()
                }
                action = request.action

                if action == "run":
                    missing = [n for n in request.secret_names if n not in secrets_map]
                    if missing:
                        reply["reason"] = f"unknown secrets: {', '.join(missing)}"
                    elif not request.command:
                        reply["reason"] = "no command"
                    else:
                        env_inject = {
                            request.inject_as.get(n, n): secrets_map[n]
                            for n in request.secret_names
                        }
                        by_name = {n: secrets_map[n] for n in request.secret_names}
                        result = run_with_secrets(
                            request.command, env_inject, by_name
                        )
                        reply["ok"] = True
                        reply["run_result"] = {
                            "exit_code": result.exit_code,
                            "scrubbed_stdout": result.scrubbed_stdout,
                            "scrubbed_stderr": result.scrubbed_stderr,
                        }
                        # Never include raw secrets in reply.

                elif action == "reveal":
                    name = request.secret_names[0] if request.secret_names else ""
                    if name not in secrets_map:
                        reply["reason"] = f"unknown secret: {name}"
                    else:
                        theme.out()
                        theme.out(f"--- {name} ---")
                        # Raw secret value — never themed.
                        sys.stdout.write(f"{secrets_map[name]}\n")
                        theme.out("--- end ---")
                        reply["ok"] = True
                        reply["status_only"] = {
                            "shown": True,
                            "action": "reveal",
                            "name": name,
                        }

                elif action == "copy":
                    name = request.secret_names[0] if request.secret_names else ""
                    if name not in secrets_map:
                        reply["reason"] = f"unknown secret: {name}"
                    else:
                        copy_to_clipboard(secrets_map[name])
                        theme.success(f"Copied '{name}' to clipboard (this window only).")
                        reply["ok"] = True
                        reply["status_only"] = {
                            "copied": True,
                            "action": "copy",
                            "name": name,
                        }

                elif action in ("set", "remove", "config", "unlock", "auth"):
                    # Auth-only: prove password works; caller (parent) cannot
                    # get the password back over IPC. For set/remove/config
                    # that need the password in the parent, those must be
                    # interactive (inline) OR the helper must perform the
                    # mutation. Per design: non-interactive set/remove/config
                    # still need fresh auth — helper will perform mutation
                    # when request carries mutation fields.
                    # For unlock/auth/set/remove/config: password verified;
                    # helper may apply mutation if detail JSON says so.
                    reply["ok"] = True
                    reply["reason"] = "authenticated"
                    # Mutation payloads arrive in request.detail as JSON for
                    # set/remove/config when parent cannot hold the password.
                    if action == "set" and request.detail:
                        try:
                            mut = json.loads(request.detail)
                            name = mut["name"]
                            value = mut["value"]
                            secrets_map[name] = value
                            from key_amnesia.vault import save_vault

                            save_vault(
                                vault,
                                password,
                                {
                                    "secrets": secrets_map,
                                    "logins": payload.get("logins") or [],
                                    "browser_associations": payload.get(
                                        "browser_associations"
                                    )
                                    or [],
                                    "database_id": payload.get("database_id") or "",
                                    "created_at": payload.get("created_at"),
                                    "updated_at": payload.get("updated_at"),
                                },
                            )
                            reply["status_only"] = {"action": "set", "name": name}
                        except Exception as e:  # noqa: BLE001
                            reply["ok"] = False
                            reply["reason"] = f"set failed: {e}"
                    elif action == "remove" and request.secret_names:
                        name = request.secret_names[0]
                        if name not in secrets_map:
                            reply["ok"] = False
                            reply["reason"] = f"unknown secret: {name}"
                        else:
                            del secrets_map[name]
                            from key_amnesia.vault import save_vault

                            save_vault(
                                vault,
                                password,
                                {
                                    "secrets": secrets_map,
                                    "logins": payload.get("logins") or [],
                                    "browser_associations": payload.get(
                                        "browser_associations"
                                    )
                                    or [],
                                    "database_id": payload.get("database_id") or "",
                                    "created_at": payload.get("created_at"),
                                    "updated_at": payload.get("updated_at"),
                                },
                            )
                            reply["status_only"] = {"action": "remove", "name": name}
                    elif action == "config" and request.detail:
                        try:
                            mut = json.loads(request.detail)
                            from key_amnesia.config import set_config_value

                            set_config_value(mut["key"], str(mut["value"]))
                            reply["status_only"] = {
                                "action": "config",
                                "key": mut["key"],
                            }
                        except Exception as e:  # noqa: BLE001
                            reply["ok"] = False
                            reply["reason"] = f"config failed: {e}"
                    elif action == "unlock":
                        # Helper cannot start guard with password over IPC.
                        # Unlock from non-interactive requires helper to start
                        # the guard itself and write lock file.
                        try:
                            from key_amnesia.guard import start_guard_process

                            timeout_min = int(
                                json.loads(request.detail or "{}").get(
                                    "session-timeout-minutes",
                                    load_config().get("session-timeout-minutes", 30),
                                )
                            )
                            start_guard_process(payload, timeout_min)
                            reply["status_only"] = {"action": "unlock"}
                        except Exception as e:  # noqa: BLE001
                            reply["ok"] = False
                            reply["reason"] = f"unlock failed: {e}"
                else:
                    reply["reason"] = f"unsupported helper action: {action}"
    finally:
        # Wipe password from locals as best-effort
        password = ""  # noqa: F841

    # Connect back to parent and send status-only reply.
    try:
        if parent_pid and not parent_alive(parent_pid):
            theme.error("Parent gone; discarding reply.")
            return 1
        conn = ipc.connect(address, authkey)
        try:
            # Final hard filter: never send password or raw secret maps.
            safe = {
                k: v
                for k, v in reply.items()
                if k in ("ok", "reason", "run_result", "status_only")
            }
            if "run_result" in safe and isinstance(safe["run_result"], dict):
                rr = safe["run_result"]
                safe["run_result"] = {
                    "exit_code": rr.get("exit_code"),
                    "scrubbed_stdout": rr.get("scrubbed_stdout", ""),
                    "scrubbed_stderr": rr.get("scrubbed_stderr", ""),
                }
            ipc.send_msg(conn, safe)
        finally:
            conn.close()
    except Exception as e:  # noqa: BLE001
        theme.error(f"Failed to reply to parent: {e}")
        input("Press Enter to close...")
        return 1

    cancel["flag"] = True
    if reply.get("ok"):
        theme.success("Done.")
    else:
        theme.out(f"Failed: {reply.get('reason', 'unknown')}")
    # Brief pause so user can read the console before it closes.
    time.sleep(0.8)
    return 0 if reply.get("ok") else 1
