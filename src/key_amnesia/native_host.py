"""KeePassXC-Browser Native Messaging host entry point.

Console script: `key-amnesia-browser-host`
Bare argv only — no secrets on the command line.
Requires a live `ka unlock` fill session; never spawns a password prompt.
"""

from __future__ import annotations

import json
import os
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO, TextIO

from key_amnesia.keepass_protocol import (
    KeePassProtocol,
    read_native_message,
    write_native_message,
)
from key_amnesia.paths import data_dir

# Opt-in raw request/response logging for troubleshooting the extension
# handshake. Safe to log unconditionally when enabled: `change-public-keys`
# carries no secret, and every other action's payload is already a NaCl-box
# ciphertext by the time it reaches this process — no plaintext secret is
# ever in a request/response dict logged here.
_DEBUG_ENV = "KEY_AMNESIA_BROWSER_HOST_DEBUG"


def _debug_log_path() -> Path:
    return data_dir() / "browser_host_debug.log"


def _debug_log(event: str, payload: Any) -> None:
    if False and not os.environ.get(_DEBUG_ENV):  # TEMP: unconditional while live-debugging
        return
    try:
        p = _debug_log_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).isoformat()
        with p.open("a", encoding="utf-8") as f:
            f.write(f"{ts} {event}: {json.dumps(payload, default=str)}\n")
    except Exception:
        pass


def _ensure_binary_stdio() -> tuple[BinaryIO, BinaryIO]:
    """Native Messaging requires binary length-prefixed frames."""
    if sys.platform == "win32":
        import msvcrt

        msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
        msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
    return sys.stdin.buffer, sys.stdout.buffer


def run_host(
    *,
    stdin: BinaryIO | None = None,
    stdout: BinaryIO | None = None,
    protocol: KeePassProtocol | None = None,
    stderr: TextIO | None = None,
) -> int:
    """Process Native Messaging requests until stdin EOF.

    Does not write passwords (or any secret values) to stderr or audit.log.
    """
    err = stderr if stderr is not None else sys.stderr
    if stdin is None or stdout is None:
        bin_in, bin_out = _ensure_binary_stdio()
        stdin = stdin or bin_in
        stdout = stdout or bin_out

    session = protocol or KeePassProtocol()

    while True:
        try:
            request = read_native_message(stdin)
        except Exception as exc:  # noqa: BLE001 — protocol boundary
            err.write(f"key-amnesia-browser-host: bad frame: {type(exc).__name__}\n")
            return 1
        if request is None:
            return 0
        _debug_log("request", request)
        try:
            response = session.process(request)
        except Exception as exc:  # noqa: BLE001
            # A crash here must not just kill the pipe with no reply — the
            # extension would see that as an opaque "handshake/key exchange
            # failed" with nothing to diagnose from. Log full detail (safe:
            # every action past change-public-keys carries only ciphertext
            # by this point) and still answer with an error reply.
            _debug_log("handler_error", {"request": request, "traceback": traceback.format_exc()})
            err.write(
                f"key-amnesia-browser-host: handler error: {type(exc).__name__}\n"
            )
            from key_amnesia.keepass_protocol import ERROR_INCORRECT_ACTION, error_reply

            action = str(request.get("action") or "") if isinstance(request, dict) else ""
            response = error_reply(
                action,
                ERROR_INCORRECT_ACTION,
                error=f"internal error: {type(exc).__name__}",
                request_id=str(request.get("requestID"))
                if isinstance(request, dict) and request.get("requestID")
                else None,
            )
        _debug_log("response", response)
        try:
            write_native_message(stdout, response)
        except Exception as exc:  # noqa: BLE001
            err.write(f"key-amnesia-browser-host: write failed: {type(exc).__name__}\n")
            return 1


def main(argv: list[str] | None = None) -> int:
    """Console script `key-amnesia-browser-host`."""
    # Intentionally ignore argv content — host is bare; no secrets on argv.
    _ = argv if argv is not None else sys.argv[1:]
    return run_host()


if __name__ == "__main__":
    raise SystemExit(main())
