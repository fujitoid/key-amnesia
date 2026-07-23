"""Tests for branded theme.py — color gates, CSI, ASCII glyph fallback."""

from __future__ import annotations

import io

import pytest

from key_amnesia import theme


class _FakeTTY:
    """Writable stream that reports as a TTY with a fixed encoding."""

    def __init__(self, encoding: str = "utf-8") -> None:
        self._buf = io.StringIO()
        self.encoding = encoding

    def isatty(self) -> bool:
        return True

    def write(self, s: str) -> int:
        return self._buf.write(s)

    def flush(self) -> None:
        self._buf.flush()

    def getvalue(self) -> str:
        return self._buf.getvalue()


class _FakePipe:
    """Writable stream that reports as a non-TTY (agent / capture path)."""

    encoding = "utf-8"

    def __init__(self) -> None:
        self._buf = io.StringIO()

    def isatty(self) -> bool:
        return False

    def write(self, s: str) -> int:
        return self._buf.write(s)

    def flush(self) -> None:
        self._buf.flush()

    def getvalue(self) -> str:
        return self._buf.getvalue()


class _FakeCp1252Console:
    """Writable stream that actually enforces a legacy codepage encoding.

    Mirrors a real Windows console using cp1252: raises UnicodeEncodeError
    on any character the codepage can't represent, exactly like the crash
    this simulates (`→`/`—`/`…` in caller message text).
    """

    encoding = "cp1252"

    def __init__(self) -> None:
        self._chunks: list[bytes] = []

    def isatty(self) -> bool:
        return False

    def write(self, s: str) -> int:
        self._chunks.append(s.encode(self.encoding))  # raises on unencodable chars
        return len(s)

    def flush(self) -> None:
        pass

    def getvalue(self) -> str:
        return b"".join(self._chunks).decode(self.encoding)


def test_unencodable_message_text_does_not_crash(monkeypatch: pytest.MonkeyPatch) -> None:
    """A caller message containing e.g. an arrow must degrade, never raise,
    on a stream whose encoding (e.g. a legacy Windows console codepage)
    can't represent it."""
    monkeypatch.setenv("NO_COLOR", "1")
    buf = _FakeCp1252Console()
    theme.success("Storebox: installed → C:\\path\\manifest.json", file=buf)
    theme.info("choice — lightest and fastest…", file=buf)
    out = buf.getvalue()
    assert "installed" in out
    assert "C:\\path\\manifest.json" in out
    assert "lightest and fastest" in out


def test_no_color_env_suppresses_escapes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NO_COLOR", "1")
    buf = _FakeTTY()
    theme.success("Vault ready", file=buf)
    theme.error("Denied: no", file=buf)
    out = buf.getvalue()
    assert "\033[" not in out
    assert "Vault ready" in out
    assert "Denied: no" in out


def test_non_tty_suppresses_escapes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    buf = _FakePipe()
    theme.success("ok line", file=buf)
    theme.error("Denied: nope", file=buf)
    theme.warn("careful", file=buf)
    theme.info("note", file=buf)
    out = buf.getvalue()
    assert "\033[" not in out
    assert "ok line" in out
    assert "Denied: nope" in out


def test_tty_color_success_uses_teal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("COLORTERM", "truecolor")
    buf = _FakeTTY()
    theme.success("Vault initialized", file=buf)
    out = buf.getvalue()
    assert "\033[38;2;0;229;255m" in out  # teal #00E5FF
    assert "\033[0m" in out
    assert "Vault initialized" in theme.strip_csi(out)


def test_tty_color_denial_uses_red(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("COLORTERM", "truecolor")
    buf = _FakeTTY()
    theme.error("Denied: timeout", file=buf)
    out = buf.getvalue()
    assert "\033[38;2;232;93;93m" in out  # denial red
    assert "Denied: timeout" in theme.strip_csi(out)


def test_non_denial_error_is_not_red(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("COLORTERM", "truecolor")
    buf = _FakeTTY()
    theme.error("Error: passwords do not match", file=buf)
    out = buf.getvalue()
    assert "\033[38;2;232;93;93m" not in out
    assert "\033[38;2;139;154;171m" in out  # slate
    assert "Error: passwords do not match" in theme.strip_csi(out)


def test_ascii_fallback_when_no_color(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NO_COLOR", "1")
    buf = _FakeTTY()
    theme.success("done", file=buf)
    theme.error("Denied: x", file=buf)
    theme.success("Locked.", file=buf)
    out = buf.getvalue()
    assert "[OK]" in out
    assert "[DENIED]" in out
    assert "[LOCKED]" in out
    assert "✓" not in out
    assert "✗" not in out
    assert "🔒" not in out


def test_ascii_fallback_on_non_tty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    buf = _FakePipe()
    theme.success("done", file=buf)
    theme.error("Denied: x", file=buf)
    out = buf.getvalue()
    assert "[OK]" in out
    assert "[DENIED]" in out


def test_unicode_glyphs_on_color_tty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("COLORTERM", "truecolor")
    buf = _FakeTTY(encoding="utf-8")
    theme.success("done", file=buf)
    theme.error("Denied: x", file=buf)
    theme.success("Locked.", file=buf)
    out = theme.strip_csi(buf.getvalue())
    assert "✓" in out
    assert "✗" in out
    assert "🔒" in out
    assert "[OK]" not in out
    assert "[DENIED]" not in out


def test_256_color_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("COLORTERM", raising=False)
    monkeypatch.delenv("WT_SESSION", raising=False)
    monkeypatch.delenv("TERM_PROGRAM", raising=False)
    monkeypatch.setenv("TERM", "xterm-256color")
    # Force non-Windows truecolor heuristics off for this unit test
    monkeypatch.setattr(theme, "_VT_ENABLED", False)
    monkeypatch.setattr(theme, "_enable_windows_vt", lambda: None)
    buf = _FakeTTY()
    theme.info("hello", file=buf)
    out = buf.getvalue()
    assert "\033[38;5;51m" in out  # teal 256
    assert "\033[38;2;" not in out


def test_warn_uses_amber(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("COLORTERM", "truecolor")
    buf = _FakeTTY()
    theme.warn("Guard session expired", file=buf)
    out = buf.getvalue()
    assert "\033[38;2;224;164;88m" in out  # amber #E0A458


def test_out_and_err_plain_message_body(monkeypatch: pytest.MonkeyPatch) -> None:
    """Lists / status stay undecorated aside from optional rule tinting."""
    monkeypatch.setenv("NO_COLOR", "1")
    buf = _FakePipe()
    theme.out("api_key", file=buf)
    theme.err("plain err", file=buf)
    out = buf.getvalue()
    assert out.splitlines() == ["api_key", "plain err"]
