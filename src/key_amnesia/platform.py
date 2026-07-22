"""OS-specific process spawn helpers for isolated-console prompts."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from typing import Any, Callable

# Linux X11/Wayland terminal emulators, tried in order (first on PATH wins).
_LINUX_EMULATORS: tuple[str, ...] = (
    "x-terminal-emulator",
    "gnome-terminal",
    "konsole",
    "xterm",
)


def _has_interactive_display() -> bool:
    return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


def _linux_emulator_argv(emulator: str, argv: list[str]) -> list[str]:
    """Build emulator + helper argv. Secrets stay in env, never on argv."""
    name = os.path.basename(emulator)
    if name == "gnome-terminal":
        # gnome-terminal deprecated -e; -- separates options from the command.
        return [emulator, "--", *argv]
    return [emulator, "-e", *argv]


def _spawn_linux(
    argv: list[str],
    env: dict[str, str],
    *,
    popen_fn: Callable[..., Any],
) -> Any:
    if not _has_interactive_display():
        raise OSError(
            "No interactive display available (DISPLAY/WAYLAND_DISPLAY unset); "
            "cannot spawn isolated console. Fail closed."
        )

    for name in _LINUX_EMULATORS:
        path = shutil.which(name)
        if not path:
            continue
        cmd = _linux_emulator_argv(path, argv)
        try:
            # No stdin/stdout/stderr kwargs — emulator owns stdio.
            return popen_fn(cmd, env=env, close_fds=True)
        except OSError:
            continue

    raise OSError(
        "No suitable terminal emulator found "
        f"(tried {', '.join(_LINUX_EMULATORS)}). Fail closed."
    )


def spawn_isolated_console(
    argv: list[str],
    env: dict[str, str],
    *,
    popen_fn: Callable[..., Any] | None = None,
) -> Any:
    """Spawn *argv* in an isolated console; sensitive data only in *env*.

    Windows: CREATE_NEW_CONSOLE, no stdio kwargs.
    Linux: first available of x-terminal-emulator / gnome-terminal / konsole /
    xterm when DISPLAY or WAYLAND_DISPLAY is set; otherwise fail closed.
    macOS and other platforms: fail closed (not yet implemented).
    """
    popen = popen_fn or subprocess.Popen

    if sys.platform == "win32":
        creationflags = subprocess.CREATE_NEW_CONSOLE  # type: ignore[attr-defined]
        # No stdin/stdout/stderr kwargs — new console owns stdio.
        return popen(
            argv,
            env=env,
            creationflags=creationflags,
            close_fds=False,
        )

    if sys.platform.startswith("linux"):
        return _spawn_linux(argv, env, popen_fn=popen)

    raise OSError(
        "Isolated-console spawn is not implemented on this platform "
        f"({sys.platform}); macOS and others remain fail-closed. Fail closed."
    )
