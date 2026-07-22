"""OS-specific process spawn helpers for isolated-console prompts."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from typing import Any, Callable, TextIO

from key_amnesia import theme

# Linux X11/Wayland terminal emulators, tried in order (first on PATH wins).
_LINUX_EMULATORS: tuple[str, ...] = (
    "x-terminal-emulator",
    "gnome-terminal",
    "konsole",
    "xterm",
)

_LINUX_EMULATOR_DESCRIPTIONS: dict[str, str] = {
    "x-terminal-emulator": "uses your distro's configured default terminal",
    "gnome-terminal": "full-featured, best if you're on GNOME",
    "konsole": "full-featured, best if you're on KDE",
    "xterm": "lightest and fastest, no desktop-environment dependencies",
}

# Package-manager detection order (first on PATH wins).
_PKG_MANAGERS: tuple[tuple[str, str], ...] = (
    ("apt-get", "sudo apt-get install {pkg}"),
    ("apt", "sudo apt install {pkg}"),
    ("dnf", "sudo dnf install {pkg}"),
    ("pacman", "sudo pacman -S {pkg}"),
    ("apk", "sudo apk add {pkg}"),
    ("zypper", "sudo zypper install {pkg}"),
)

# Brief pause after spawn to catch an emulator that launches then exits right
# away (e.g. a broken alias, or a build that doesn't accept our -e/-- flag).
# Overridable so tests don't pay this cost.
_POLL_DELAY_S = 0.15


def _has_interactive_display() -> bool:
    return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


def _linux_emulator_argv(emulator: str, argv: list[str]) -> list[str]:
    """Build emulator + helper argv. Secrets stay in env, never on argv."""
    name = os.path.basename(emulator)
    if name == "gnome-terminal":
        # gnome-terminal deprecated -e; -- separates options from the command.
        return [emulator, "--", *argv]
    return [emulator, "-e", *argv]


def _process_alive(proc: Any) -> bool:
    """Best-effort liveness check shortly after spawn.

    Treat a stub without a working `.poll()` (e.g. an unconfigured test
    double) as alive rather than reject it — this only needs to catch a
    *real* process that has already exited.
    """
    poll = getattr(proc, "poll", None)
    if not callable(poll):
        return True
    try:
        return poll() is None
    except Exception:
        return True


def _no_emulator_oserror() -> OSError:
    return OSError(
        "No suitable terminal emulator found "
        f"(tried {', '.join(_LINUX_EMULATORS)}). Fail closed."
    )


def _open_controlling_tty() -> TextIO | None:
    """Open the controlling terminal, or None if unavailable."""
    try:
        return open("/dev/tty", "r+", encoding="utf-8", errors="replace")
    except OSError:
        return None


def _tty_readline(tty: TextIO, prompt: str) -> str:
    tty.write(prompt)
    tty.flush()
    return tty.readline().strip()


def _pkg_install_command(package: str) -> str | None:
    """Return a one-line install command for *package*, or None if unknown pm."""
    for binary, template in _PKG_MANAGERS:
        if shutil.which(binary):
            return template.format(pkg=package)
    return None


def _try_spawn_linux_emulators(
    argv: list[str],
    env: dict[str, str],
    *,
    popen_fn: Callable[..., Any],
) -> tuple[Any | None, list[str]]:
    """Try each known emulator on PATH. Return (proc_or_None, names_tried)."""
    tried: list[str] = []
    for name in _LINUX_EMULATORS:
        path = shutil.which(name)
        if not path:
            continue
        tried.append(name)
        cmd = _linux_emulator_argv(path, argv)
        try:
            # No stdin/stdout/stderr kwargs — emulator owns stdio.
            proc = popen_fn(cmd, env=env, close_fds=True)
        except OSError:
            continue
        if _POLL_DELAY_S:
            time.sleep(_POLL_DELAY_S)
        if _process_alive(proc):
            return proc, tried
        # Launched but exited immediately (bad invocation, broken alias) —
        # don't report false success; try the next emulator instead.
        continue
    return None, tried


def _offer_linux_emulator_install(
    argv: list[str],
    env: dict[str, str],
    *,
    popen_fn: Callable[..., Any],
) -> Any | None:
    """Interactive /dev/tty recovery when no emulator is on PATH.

    Returns a live process if the user installs and retry succeeds; otherwise
    None (caller raises the existing OSError). Never prompts on the headless
    branch — that path never reaches here. Never asks for a password.
    """
    tty = _open_controlling_tty()
    if tty is None:
        return None

    err = _no_emulator_oserror()
    try:
        theme.warn(str(err), file=tty)
        answer = _tty_readline(tty, "Install one now? [y/N] ").strip().lower()
        if answer not in ("y", "yes"):
            return None

        theme.info("Choose a terminal emulator to install:", file=tty)
        for i, name in enumerate(_LINUX_EMULATORS, start=1):
            desc = _LINUX_EMULATOR_DESCRIPTIONS.get(name, "")
            theme.info(f"  {i}) {name} — {desc}", file=tty)
        skip_n = len(_LINUX_EMULATORS) + 1
        theme.info(f"  {skip_n}) skip, don't install anything", file=tty)

        choice_raw = _tty_readline(tty, "Choice: ").strip()
        try:
            choice = int(choice_raw)
        except ValueError:
            return None
        if choice == skip_n or choice < 1 or choice > skip_n:
            return None

        package = _LINUX_EMULATORS[choice - 1]
        cmd = _pkg_install_command(package)
        if cmd is not None:
            theme.info("Run this in another shell (not executed by key-amnesia):", file=tty)
            theme.out(f"  {cmd}", file=tty)
        else:
            theme.info(
                f"Install package '{package}' with your distro's package manager "
                "(no known package manager found on PATH).",
                file=tty,
            )
        _tty_readline(tty, "Press Enter after installing… ")

        retry = _tty_readline(tty, "Installed it? Retry now? [y/N] ").strip().lower()
        if retry not in ("y", "yes"):
            return None

        proc, tried = _try_spawn_linux_emulators(argv, env, popen_fn=popen_fn)
        if proc is not None:
            return proc
        if tried:
            # Found but none stayed running — surface the same message as the
            # normal path rather than the "none on PATH" OSError.
            raise OSError(
                f"Terminal emulator(s) found ({', '.join(tried)}) but none stayed "
                "running (bad invocation or immediate exit). Fail closed."
            )
        return None
    finally:
        try:
            tty.close()
        except Exception:
            pass


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

    proc, tried = _try_spawn_linux_emulators(argv, env, popen_fn=popen_fn)
    if proc is not None:
        return proc

    if tried:
        raise OSError(
            f"Terminal emulator(s) found ({', '.join(tried)}) but none stayed "
            "running (bad invocation or immediate exit). Fail closed."
        )

    # Display present, nothing on PATH — one interactive install offer via /dev/tty.
    offered = _offer_linux_emulator_install(argv, env, popen_fn=popen_fn)
    if offered is not None:
        return offered
    raise _no_emulator_oserror()


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
