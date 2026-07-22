"""KeePassXC-Browser Native Messaging host entry point.

Console script: `key-amnesia-browser-host`
Bare argv only — no secrets on the command line.
Requires a live `ka unlock` fill session; never spawns a password prompt.
"""

from __future__ import annotations

import os
import sys
from typing import BinaryIO, TextIO

from key_amnesia.keepass_protocol import (
    KeePassProtocol,
    read_native_message,
    write_native_message,
)


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
        try:
            response = session.process(request)
            write_native_message(stdout, response)
        except Exception as exc:  # noqa: BLE001
            err.write(
                f"key-amnesia-browser-host: handler error: {type(exc).__name__}\n"
            )
            return 1


def main(argv: list[str] | None = None) -> int:
    """Console script `key-amnesia-browser-host`."""
    # Intentionally ignore argv content — host is bare; no secrets on argv.
    _ = argv if argv is not None else sys.argv[1:]
    return run_host()


if __name__ == "__main__":
    raise SystemExit(main())
