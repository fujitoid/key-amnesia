"""Linux isolated-console spawn: emulator choice, env handoff, fail-closed."""

from __future__ import annotations

import sys
from typing import Any
from unittest.mock import MagicMock

import pytest

from key_amnesia.platform import spawn_isolated_console


HELPER_ARGV = [sys.executable, "-m", "key_amnesia", "_prompt-helper"]
SENSITIVE_ENV = {
    "PATH": "/usr/bin",
    "KEY_AMNESIA_PROMPT_REQUEST": '{"action":"reveal","secret_names":["api_key"]}',
    "KEY_AMNESIA_PROMPT_AUTHKEY": "a" * 64,
    "KEY_AMNESIA_PROMPT_ADDRESS": "/tmp/key-amnesia-test.sock",
    "DISPLAY": ":0",
}


def _fake_which(available: dict[str, str]):
    def which(name: str) -> str | None:
        return available.get(name)

    return which


def test_linux_prefers_x_terminal_emulator(monkeypatch) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setenv("DISPLAY", ":0")
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    monkeypatch.setattr(
        "key_amnesia.platform.shutil.which",
        _fake_which(
            {
                "x-terminal-emulator": "/usr/bin/x-terminal-emulator",
                "gnome-terminal": "/usr/bin/gnome-terminal",
                "xterm": "/usr/bin/xterm",
            }
        ),
    )
    captured: dict[str, Any] = {}

    def fake_popen(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        return MagicMock()

    spawn_isolated_console(HELPER_ARGV, dict(SENSITIVE_ENV), popen_fn=fake_popen)

    cmd = captured["cmd"]
    assert cmd[0] == "/usr/bin/x-terminal-emulator"
    assert cmd[1] == "-e"
    assert cmd[2:] == HELPER_ARGV
    assert "_prompt-helper" in cmd
    joined = " ".join(cmd)
    assert "api_key" not in joined
    assert "authkey" not in joined.lower()
    assert "a" * 64 not in joined

    kwargs = captured["kwargs"]
    assert "stdin" not in kwargs
    assert "stdout" not in kwargs
    assert "stderr" not in kwargs
    assert kwargs["env"]["KEY_AMNESIA_PROMPT_AUTHKEY"] == "a" * 64
    assert kwargs["env"]["KEY_AMNESIA_PROMPT_REQUEST"]


def test_linux_falls_through_to_gnome_terminal(monkeypatch) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setenv("WAYLAND_DISPLAY", "wayland-0")
    monkeypatch.delenv("DISPLAY", raising=False)
    monkeypatch.setattr(
        "key_amnesia.platform.shutil.which",
        _fake_which({"gnome-terminal": "/usr/bin/gnome-terminal"}),
    )
    captured: dict[str, Any] = {}

    def fake_popen(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        return MagicMock()

    spawn_isolated_console(HELPER_ARGV, dict(SENSITIVE_ENV), popen_fn=fake_popen)

    assert captured["cmd"] == [
        "/usr/bin/gnome-terminal",
        "--",
        *HELPER_ARGV,
    ]


def test_linux_konsole_and_xterm_wiring(monkeypatch) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setenv("DISPLAY", ":1")

    for name, path in (
        ("konsole", "/usr/bin/konsole"),
        ("xterm", "/usr/bin/xterm"),
    ):
        monkeypatch.setattr(
            "key_amnesia.platform.shutil.which",
            _fake_which({name: path}),
        )
        captured: dict[str, Any] = {}

        def fake_popen(cmd, **kwargs):
            captured["cmd"] = cmd
            return MagicMock()

        spawn_isolated_console(HELPER_ARGV, dict(SENSITIVE_ENV), popen_fn=fake_popen)
        assert captured["cmd"] == [path, "-e", *HELPER_ARGV]


def test_linux_headless_fail_closed(monkeypatch) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.delenv("DISPLAY", raising=False)
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)

    with pytest.raises(OSError, match="DISPLAY/WAYLAND_DISPLAY|Fail closed"):
        spawn_isolated_console(HELPER_ARGV, dict(SENSITIVE_ENV), popen_fn=MagicMock())


def test_linux_no_emulator_fail_closed(monkeypatch) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setenv("DISPLAY", ":0")
    monkeypatch.setattr(
        "key_amnesia.platform.shutil.which",
        _fake_which({}),
    )

    with pytest.raises(OSError, match="terminal emulator|Fail closed"):
        spawn_isolated_console(HELPER_ARGV, dict(SENSITIVE_ENV), popen_fn=MagicMock())


def test_darwin_fail_closed(monkeypatch) -> None:
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setenv("DISPLAY", ":0")

    with pytest.raises(OSError, match="not implemented|Fail closed"):
        spawn_isolated_console(HELPER_ARGV, dict(SENSITIVE_ENV), popen_fn=MagicMock())


def test_other_platform_fail_closed(monkeypatch) -> None:
    monkeypatch.setattr(sys, "platform", "freebsd14")

    with pytest.raises(OSError, match="not implemented|Fail closed"):
        spawn_isolated_console(HELPER_ARGV, dict(SENSITIVE_ENV), popen_fn=MagicMock())
