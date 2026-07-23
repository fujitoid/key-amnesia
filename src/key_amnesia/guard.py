"""Cached-session guard — foreground singleton holding decrypted vault in memory.

IPC verbs: run, list, lock, status, renew only.
Never returns raw secret values. No get-value / reveal verb.
Authkey only (no session_key).

`ka unlock` *is* the guard: unlike v2, there is no detached child process and
no bootstrap-env handoff. `run_foreground_guard` runs in the caller's own
terminal, printing live status lines and blocking in `guard_serve` until the
vault is locked, the session expires, or the terminal is interrupted. A
lightweight admission-consent layer sits on top of the authkey trust
boundary: the first request from any client is gated by a yes/no prompt on
the guard's own TTY; once admitted, that opaque token skips the prompt for
the rest of the guard's lifetime.
"""

from __future__ import annotations

import json
import os
import secrets as secrets_mod
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from multiprocessing.connection import Connection
from pathlib import Path
from typing import Any, Callable

from key_amnesia import ipc
from key_amnesia import theme
from key_amnesia.audit import audit_event
from key_amnesia.paths import (
    admitted_session_token_path,
    guard_lock_path,
    last_guard_state_path,
)
from key_amnesia.run_exec import run_with_secrets

AdmitPromptFn = Callable[[int, str], bool]

# How long the guard's admission prompt waits for a yes/no before denying.
ADMISSION_TIMEOUT_S = 60.0


@dataclass
class AdmittedSession:
    """One in-memory admitted client record — lives only for this guard run."""

    token: str
    first_seen: str
    request_count: int = 0
    last_summary: str = ""


@dataclass
class GuardState:
    secrets: dict[str, str]
    expires_at: float  # epoch seconds
    address: str
    authkey: bytes
    pid: int = field(default_factory=os.getpid)
    created_at: float = field(default_factory=time.time)
    stop: threading.Event = field(default_factory=threading.Event)
    admitted: AdmittedSession | None = None
    request_count: int = 0


def _utc_iso(ts: float | None = None) -> str:
    t = ts if ts is not None else time.time()
    return datetime.fromtimestamp(t, tz=timezone.utc).replace(microsecond=0).isoformat()


# --- guard.lock ---------------------------------------------------------


def write_guard_lock(
    address: str,
    authkey: bytes,
    pid: int,
    expires_at: float,
    path: Path | None = None,
) -> None:
    p = path or guard_lock_path()
    data = {
        "address": address,
        "authkey_hex": ipc.authkey_to_hex(authkey),
        "pid": pid,
        "expires_at": _utc_iso(expires_at),
        "expires_at_epoch": expires_at,
    }
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def read_guard_lock(path: Path | None = None) -> dict[str, Any] | None:
    p = path or guard_lock_path()
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    return data


def clear_guard_lock(path: Path | None = None) -> None:
    p = path or guard_lock_path()
    try:
        p.unlink(missing_ok=True)
    except OSError:
        pass


def guard_is_alive(lock: dict[str, Any] | None = None) -> bool:
    lock = lock if lock is not None else read_guard_lock()
    if not lock:
        return False
    pid = int(lock.get("pid") or 0)
    expires = float(lock.get("expires_at_epoch") or 0)
    if expires and time.time() > expires:
        return False
    if pid <= 0:
        return False
    from key_amnesia.prompt_route import parent_alive

    return parent_alive(pid)


def connect_guard(lock: dict[str, Any] | None = None) -> Connection | None:
    lock = lock if lock is not None else read_guard_lock()
    if not lock or not guard_is_alive(lock):
        return None
    try:
        authkey = ipc.authkey_from_hex(lock["authkey_hex"])
        return ipc.connect(lock["address"], authkey)
    except Exception:
        return None


# --- admission token file (client-side cache of the guard's opaque token) --


def read_admission_token(path: Path | None = None) -> str | None:
    p = path or admitted_session_token_path()
    if not p.exists():
        return None
    try:
        text = p.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return text or None


def write_admission_token(token: str, path: Path | None = None) -> None:
    p = path or admitted_session_token_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(token + "\n", encoding="utf-8")


def clear_admission_token(path: Path | None = None) -> None:
    p = path or admitted_session_token_path()
    try:
        p.unlink(missing_ok=True)
    except OSError:
        pass


def guard_request(msg: dict[str, Any], timeout: float = 30.0) -> dict[str, Any] | None:
    """Send a message to the live guard; return response or None.

    Centralizes admission-token plumbing so call sites (cmd_run / cmd_list /
    cmd_lock / cmd_status / ...) stay thin: attaches the caller's pid and any
    cached admission token to every outgoing message, and persists a fresh
    token the guard hands back after admitting this client.
    """
    conn = connect_guard()
    if conn is None:
        return None
    out = dict(msg)
    out.setdefault("caller_pid", os.getpid())
    token = read_admission_token()
    if token:
        out.setdefault("admission_token", token)
    try:
        ipc.send_msg(conn, out)
        reply = ipc.recv_msg(conn, timeout=timeout)
    except Exception:
        return None
    finally:
        try:
            conn.close()
        except Exception:
            pass
    new_token = reply.get("admission_token") if isinstance(reply, dict) else None
    if new_token:
        write_admission_token(str(new_token))
    return reply


# --- admission consent ----------------------------------------------------


def _summarize_request(verb: str, msg: dict[str, Any]) -> str:
    if verb == "run":
        cmd = " ".join(str(c) for c in (msg.get("command") or []))
        return f"run `{cmd}`" if cmd else "run a command"
    if verb == "list":
        return "list secret names"
    if verb == "status":
        return "check guard status"
    if verb == "lock":
        return "lock the vault"
    if verb == "renew":
        return f"renew the session ({msg.get('minutes', '?')}m)"
    return f"'{verb or 'unknown'}' request"


def default_admit_prompt(caller_pid: int, summary: str) -> bool:
    """Blocking yes/no prompt on the guard's own foreground TTY.

    Bounded by ADMISSION_TIMEOUT_S on a daemon thread — same fail-closed
    pattern as the inline prompts in prompt_route.py: deny on timeout, EOF,
    or any non-yes answer.
    """
    try:
        theme.out(
            f"Session (pid {caller_pid}) wants: {summary}. Admit? [y/N] ",
            end="",
        )
    except Exception:
        pass

    outcome: dict[str, Any] = {}

    def _read() -> None:
        try:
            outcome["ans"] = input().strip().lower()
        except BaseException as exc:  # noqa: BLE001 — relayed via outcome
            outcome["error"] = exc

    t = threading.Thread(target=_read, daemon=True)
    t.start()
    t.join(timeout=ADMISSION_TIMEOUT_S)
    if t.is_alive() or "error" in outcome:
        return False
    return outcome.get("ans") in ("y", "yes")


def _check_admission(
    msg: dict[str, Any],
    state: GuardState,
    verb: str,
    admit_prompt: AdmitPromptFn | None,
) -> tuple[bool, str | None]:
    """Return (admitted, new_token_or_None).

    Known token matching state.admitted skips the prompt entirely (no
    re-prompt for the rest of this guard's lifetime). Missing/unknown token
    triggers a fresh consent prompt; a fresh opaque token is minted only on
    the *first* successful admission for this guard run.
    """
    token = str(msg.get("admission_token") or "")
    caller_pid = int(msg.get("caller_pid") or 0)

    if state.admitted is not None and token and token == state.admitted.token:
        state.admitted.request_count += 1
        state.admitted.last_summary = _summarize_request(verb, msg)
        return True, None

    prompt = admit_prompt or default_admit_prompt
    summary = _summarize_request(verb, msg)
    approved = bool(prompt(caller_pid, summary))
    if not approved:
        return False, None

    new_token = secrets_mod.token_urlsafe(32)
    state.admitted = AdmittedSession(
        token=new_token,
        first_seen=_utc_iso(),
        request_count=1,
        last_summary=summary,
    )
    return True, new_token


# --- verb dispatch ----------------------------------------------------------


def _dispatch_verb(verb: str, msg: dict[str, Any], state: GuardState) -> dict[str, Any]:
    if time.time() > state.expires_at and verb not in ("lock", "status"):
        return {"ok": False, "reason": "session expired", "expired": True}

    if verb == "status":
        return {
            "ok": True,
            "pid": state.pid,
            "expires_at": _utc_iso(state.expires_at),
            "expires_at_epoch": state.expires_at,
            "secret_count": len(state.secrets),
            "expired": time.time() > state.expires_at,
            "admitted": state.admitted is not None,
            "admitted_since": state.admitted.first_seen if state.admitted else None,
            "request_count": state.admitted.request_count if state.admitted else 0,
        }

    if verb == "list":
        names = sorted(state.secrets.keys())
        audit_event(
            "list",
            secret_names=names,
            route="guard-session",
            result="allowed",
        )
        return {"ok": True, "names": names}

    if verb == "lock":
        audit_event("lock", route="guard-session", result="allowed")
        state.stop.set()
        clear_admission_token()
        return {"ok": True, "lock": True}

    if verb == "renew":
        minutes = int(msg.get("minutes") or 30)
        if minutes < 1:
            return {"ok": False, "reason": "invalid minutes"}
        state.expires_at = time.time() + minutes * 60
        write_guard_lock(state.address, state.authkey, state.pid, state.expires_at)
        audit_event(
            "renew",
            route="guard-session",
            result="allowed",
            reason=f"extended {minutes}m",
        )
        return {
            "ok": True,
            "expires_at": _utc_iso(state.expires_at),
            "expires_at_epoch": state.expires_at,
        }

    if verb == "run":
        secret_names = list(msg.get("secret_names") or [])
        inject_as = dict(msg.get("inject_as") or {})
        command = list(msg.get("command") or [])
        cwd = msg.get("cwd") or None
        if not command:
            return {"ok": False, "reason": "no command"}
        missing = [n for n in secret_names if n not in state.secrets]
        if missing:
            audit_event(
                "run",
                secret_names=secret_names,
                command=command,
                route="guard-session",
                result="denied",
                reason=f"unknown secrets: {', '.join(missing)}",
            )
            return {"ok": False, "reason": f"unknown secrets: {', '.join(missing)}"}
        env_inject = {
            inject_as.get(n, n): state.secrets[n] for n in secret_names
        }
        by_name = {n: state.secrets[n] for n in secret_names}
        result = run_with_secrets(command, env_inject, by_name, cwd=cwd)
        audit_event(
            "run",
            secret_names=secret_names,
            command=command,
            route="guard-session",
            result="allowed",
        )
        # Scrubbed I/O + exit only — never raw values.
        return {
            "ok": True,
            "exit_code": result.exit_code,
            "scrubbed_stdout": result.scrubbed_stdout,
            "scrubbed_stderr": result.scrubbed_stderr,
        }

    # Explicitly reject any attempt to fetch values.
    if verb in ("get-value", "reveal", "get", "copy"):
        audit_event(
            verb,
            route="guard-session",
            result="denied",
            reason="guard has no value-return verbs",
        )
        return {"ok": False, "reason": "guard does not expose secret values"}

    return {"ok": False, "reason": f"unknown verb: {verb}"}


def guard_handle_message(
    msg: dict[str, Any],
    state: GuardState,
    *,
    admit_prompt: AdmitPromptFn | None = None,
) -> dict[str, Any]:
    """Handle one guard IPC message. Never returns raw secret values.

    Authkey check happens at the IPC layer (Listener/Client) before this
    function ever sees the message. On top of that, every verb is gated by
    admission consent: a client presenting a missing/unknown token triggers
    a yes/no prompt on the guard's own TTY (see `_check_admission`); a client
    presenting the current admitted token skips straight to dispatch.
    """
    if not isinstance(msg, dict):
        return {"ok": False, "reason": "invalid message"}

    verb = str(msg.get("verb") or msg.get("action") or "")
    state.request_count += 1

    admitted, new_token = _check_admission(msg, state, verb, admit_prompt)
    if not admitted:
        return {"ok": False, "reason": "admission denied", "admitted": False}

    reply = _dispatch_verb(verb, msg, state)
    if new_token:
        reply["admission_token"] = new_token
    return reply


# --- serve loop + honest death reporting -----------------------------------


def guard_serve(state: GuardState, listener: Any) -> str:
    """Main guard loop: accept connections until lock or expiry.

    Returns the exit reason ("locked" or "expired"); KeyboardInterrupt and
    any other exception propagate to the caller (`run_foreground_guard`) so
    it can record an honest death reason.
    """
    extend_prompted = False
    reason = "expired"
    while not state.stop.is_set():
        now = time.time()
        # ~2 min before expiry: prompt extend if TTY still interactive
        if (
            not extend_prompted
            and state.expires_at - now <= 120
            and state.expires_at > now
            and sys.stdin.isatty()
        ):
            extend_prompted = True
            try:
                theme.out(
                    f"key-amnesia guard: session expires in "
                    f"{int(state.expires_at - now)}s. Extend? [y/N] ",
                    end="",
                )
                ans = input().strip().lower()
                if ans in ("y", "yes"):
                    # Default extend by original remaining window or 30m
                    state.expires_at = time.time() + 30 * 60
                    write_guard_lock(
                        state.address, state.authkey, state.pid, state.expires_at
                    )
                    extend_prompted = False
            except (EOFError, KeyboardInterrupt):
                pass

        if now > state.expires_at:
            state.stop.set()
            reason = "expired"
            break

        # Accept with short poll via thread-less approach: use listener
        # backlog — on Windows named pipes accept blocks. Use a timeout
        # wrapper by setting a short wait via polling thread in serve_forever
        # alternative: accept in thread with stop flag.
        conn: Connection | None = None
        accepted: list[Any] = []

        def _accept() -> None:
            try:
                accepted.append(listener.accept())
            except Exception as e:  # noqa: BLE001
                accepted.append(e)

        t = threading.Thread(target=_accept, daemon=True)
        t.start()
        while t.is_alive():
            if state.stop.is_set() or time.time() > state.expires_at:
                break
            t.join(timeout=0.5)
        if not accepted:
            # Timed out waiting / expired / stop
            if state.stop.is_set():
                break
            if time.time() > state.expires_at:
                reason = "expired"
                break
            continue
        item = accepted[0]
        if isinstance(item, Exception):
            continue
        conn = item
        try:
            msg = ipc.recv_msg(conn, timeout=30.0)
            verb = str(msg.get("verb") or msg.get("action") or "") if isinstance(msg, dict) else "?"
            reply = guard_handle_message(msg, state)
            ipc.send_msg(conn, reply)
            theme.info(f"guard: {verb or '?'} -> {'ok' if reply.get('ok') else 'denied'}")
            if reply.get("lock"):
                state.stop.set()
                reason = "locked"
                break
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    state.stop.set()
    # Wipe secrets from state
    state.secrets.clear()
    return reason


def _write_last_guard_state(
    reason: str,
    started_at: float,
    request_count: int,
    path: Path | None = None,
) -> None:
    p = path or last_guard_state_path()
    data = {
        "started_at": _utc_iso(started_at),
        "ended_at": _utc_iso(),
        "reason": reason,
        "request_count": request_count,
    }
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def read_last_guard_state(path: Path | None = None) -> dict[str, Any] | None:
    p = path or last_guard_state_path()
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    return data


def _reason_phrase(last: dict[str, Any]) -> str:
    reason = str(last.get("reason") or "unknown")
    if reason == "expired":
        try:
            started = datetime.fromisoformat(str(last.get("started_at")))
            ended = datetime.fromisoformat(str(last.get("ended_at")))
            minutes = max(0, round((ended - started).total_seconds() / 60))
            return f"expired after {minutes}m"
        except (ValueError, TypeError):
            return "expired"
    return reason


def format_no_guard_message(path: Path | None = None) -> str:
    """Honest "no live guard" message used by cmd_lock / cmd_status.

    Prefers reporting the *actual* outcome of the last session over a bare
    "No active guard session." — e.g. "Last session ended 14:32 (expired
    after 30m, handled 4 requests)."
    """
    last = read_last_guard_state(path)
    if not last:
        return "Guard is not running. No previous session recorded."
    ended_at = str(last.get("ended_at") or "")
    try:
        time_part = datetime.fromisoformat(ended_at).strftime("%H:%M")
    except ValueError:
        time_part = ended_at
    count = int(last.get("request_count") or 0)
    plural = "" if count == 1 else "s"
    return (
        f"Guard is not running. Last session ended {time_part} "
        f"({_reason_phrase(last)}, handled {count} request{plural})."
    )


def run_foreground_guard(payload: dict[str, Any], timeout_minutes: int) -> int:
    """`ka unlock`'s foreground body: build state, serve, block until done.

    Runs entirely in the caller's own terminal — no subprocess, no bootstrap
    JSON handoff. Writes guard.lock for other terminals' soft-singleton check
    and prints a status line, then blocks in guard_serve. On every exit path
    (locked / expired / interrupted / crashed) writes last_guard_state.json
    with an honest reason before clearing guard.lock.
    """
    secrets_map = {k: str(v) for k, v in payload.get("secrets", {}).items()}
    expires_at = time.time() + timeout_minutes * 60
    listener, address, authkey = ipc.start_listener()
    pid = os.getpid()
    state = GuardState(
        secrets=secrets_map,
        expires_at=expires_at,
        address=address,
        authkey=authkey,
        pid=pid,
    )
    write_guard_lock(address, authkey, pid, expires_at)
    clear_admission_token()
    started_at = state.created_at

    theme.success(
        f"Guard listening (pid {pid}, timeout {timeout_minutes}m). "
        "Waiting for requests..."
    )

    reason = "expired"
    try:
        reason = guard_serve(state, listener)
    except KeyboardInterrupt:
        reason = "interrupted"
        uptime = int(time.time() - started_at)
        theme.info(
            f"Guard interrupted after {uptime}s uptime, "
            f"{state.request_count} request(s) handled, "
            f"admitted={'yes' if state.admitted else 'no'}."
        )
    except Exception as exc:  # noqa: BLE001 — honest crash reporting, then re-raise-free exit
        reason = f"crashed: {type(exc).__name__}"
        theme.error(f"Guard crashed: {exc}")
    finally:
        _write_last_guard_state(reason, started_at, state.request_count)
        state.secrets.clear()
        clear_guard_lock()
        clear_admission_token()
        try:
            listener.close()
        except Exception:
            pass
    return 0
