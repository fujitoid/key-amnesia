"""Cached-session guard process — holds decrypted vault in memory.

IPC verbs: run, list, lock, status, renew only.
Never returns raw secret values. No get-value / reveal verb.
Authkey only (no session_key).
"""

from __future__ import annotations

import json
import os
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from multiprocessing.connection import Connection
from pathlib import Path
from typing import Any

from key_amnesia import ipc
from key_amnesia import theme
from key_amnesia.audit import audit_event
from key_amnesia.paths import guard_lock_path
from key_amnesia.run_exec import run_with_secrets
from key_amnesia.vault import read_names


@dataclass
class GuardState:
    secrets: dict[str, str]
    expires_at: float  # epoch seconds
    address: str
    authkey: bytes
    pid: int = field(default_factory=os.getpid)
    created_at: float = field(default_factory=time.time)


def _utc_iso(ts: float | None = None) -> str:
    t = ts if ts is not None else time.time()
    return datetime.fromtimestamp(t, tz=timezone.utc).replace(microsecond=0).isoformat()


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


def guard_request(msg: dict[str, Any], timeout: float = 30.0) -> dict[str, Any] | None:
    """Send a message to the live guard; return response or None."""
    conn = connect_guard()
    if conn is None:
        return None
    try:
        ipc.send_msg(conn, msg)
        return ipc.recv_msg(conn, timeout=timeout)
    except Exception:
        return None
    finally:
        try:
            conn.close()
        except Exception:
            pass


def guard_handle_message(msg: dict[str, Any], state: GuardState) -> dict[str, Any]:
    """Handle one guard IPC message. Never returns raw secret values."""
    if not isinstance(msg, dict):
        return {"ok": False, "reason": "invalid message"}

    verb = str(msg.get("verb") or msg.get("action") or "")

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
        result = run_with_secrets(command, env_inject, by_name)
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


def guard_serve(state: GuardState, listener: Any) -> None:
    """Main guard loop: accept connections until lock or expiry."""
    extend_prompted = False
    while True:
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

        import threading

        t = threading.Thread(target=_accept, daemon=True)
        t.start()
        while t.is_alive():
            if time.time() > state.expires_at:
                break
            t.join(timeout=0.5)
        if not accepted:
            # Timed out waiting / expired
            if time.time() > state.expires_at:
                break
            continue
        item = accepted[0]
        if isinstance(item, Exception):
            continue
        conn = item
        try:
            msg = ipc.recv_msg(conn, timeout=30.0)
            reply = guard_handle_message(msg, state)
            ipc.send_msg(conn, reply)
            if reply.get("lock"):
                break
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    # Wipe secrets from state
    state.secrets.clear()
    clear_guard_lock()
    try:
        listener.close()
    except Exception:
        pass


def start_guard_process(payload: dict[str, Any], timeout_minutes: int) -> int:
    """Start guard in a child process holding decrypted secrets.

    Returns child PID. Writes guard.lock (authkey only — no session_key).
    """
    import subprocess

    secrets_map = {k: str(v) for k, v in payload.get("secrets", {}).items()}
    # Pass secrets to child via a one-shot pipe file that child deletes —
    # NOT on argv. Use env with a temp file path.
    import tempfile

    expires_at = time.time() + timeout_minutes * 60
    listener, address, authkey = ipc.start_listener()
    # We need the child to own the listener. Simpler approach: run guard
    # inline in a multiprocessing Process so we can pass state in memory.
    from multiprocessing import Process

    state = GuardState(
        secrets=secrets_map,
        expires_at=expires_at,
        address=address,
        authkey=authkey,
    )

    def _run() -> None:
        # Re-bind pid in child
        state.pid = os.getpid()
        write_guard_lock(address, authkey, state.pid, expires_at)
        guard_serve(state, listener)

    # Close listener in parent after fork isn't available on Windows the same
    # way — use spawn. Pass via Process target with pickled state.
    # Listener objects may not pickle. Alternative: child creates its own
    # listener and parent waits for lock file.
    listener.close()

    # Write a short-lived bootstrap file (secrets) that child reads + deletes.
    boot = tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        delete=False,
        prefix="ka-guard-",
        suffix=".json",
    )
    try:
        json.dump(
            {
                "secrets": secrets_map,
                "expires_at": expires_at,
                "timeout_minutes": timeout_minutes,
            },
            boot,
        )
        boot.close()
        boot_path = boot.name
        env = os.environ.copy()
        env["KEY_AMNESIA_GUARD_BOOTSTRAP"] = boot_path
        # Bare argv — no secrets.
        cmd = [sys.executable, "-m", "key_amnesia", "_guard"]
        creationflags = 0
        if sys.platform == "win32":
            # DETACHED so guard outlives the unlock terminal optionally;
            # still same-user. Use CREATE_NEW_PROCESS_GROUP.
            creationflags = subprocess.CREATE_NEW_PROCESS_GROUP  # type: ignore[attr-defined]
        proc = subprocess.Popen(
            cmd,
            env=env,
            creationflags=creationflags,
            close_fds=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        # Wait for lock file to appear
        deadline = time.time() + 15
        while time.time() < deadline:
            lock = read_guard_lock()
            if lock and int(lock.get("pid") or 0) == proc.pid:
                return proc.pid
            if proc.poll() is not None:
                raise RuntimeError("guard process exited before writing lock")
            time.sleep(0.05)
        raise RuntimeError("guard failed to start (no lock file)")
    finally:
        # Parent must not leave bootstrap around if child never started
        pass


def run_guard_main() -> int:
    """Entry for `_guard`: read bootstrap env, serve, exit."""
    boot_path = os.environ.pop("KEY_AMNESIA_GUARD_BOOTSTRAP", "")
    if not boot_path:
        theme.error("guard: missing bootstrap")
        return 1
    try:
        with open(boot_path, encoding="utf-8") as f:
            boot = json.load(f)
    finally:
        try:
            Path(boot_path).unlink(missing_ok=True)
        except OSError:
            pass

    secrets_map = {k: str(v) for k, v in boot.get("secrets", {}).items()}
    expires_at = float(boot["expires_at"])
    listener, address, authkey = ipc.start_listener()
    pid = os.getpid()
    write_guard_lock(address, authkey, pid, expires_at)
    state = GuardState(
        secrets=secrets_map,
        expires_at=expires_at,
        address=address,
        authkey=authkey,
        pid=pid,
    )
    try:
        guard_serve(state, listener)
    finally:
        state.secrets.clear()
        clear_guard_lock()
    return 0
