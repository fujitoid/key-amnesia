"""OS-specific process spawn helpers (Phase 0: Windows CREATE_NEW_CONSOLE only)."""

from __future__ import annotations

import subprocess
import sys
from typing import Any, Callable


def spawn_isolated_console(
    argv: list[str],
    env: dict[str, str],
    *,
    popen_fn: Callable[..., Any] | None = None,
) -> Any:
    """Spawn *argv* in an isolated console; sensitive data only in *env*.

    Windows: CREATE_NEW_CONSOLE, no stdio kwargs.
    Non-win32: fail closed (POSIX console spawn is out of scope for v0).
    """
    if sys.platform != "win32":
        raise OSError(
            "Non-interactive prompt spawn is Windows-only in v0; "
            "POSIX console spawn is out of scope. Fail closed."
        )

    creationflags = subprocess.CREATE_NEW_CONSOLE  # type: ignore[attr-defined]
    popen = popen_fn or subprocess.Popen
    # No stdin/stdout/stderr kwargs — new console owns stdio.
    return popen(
        argv,
        env=env,
        creationflags=creationflags,
        close_fds=False,
    )
