"""CLI tests for ka login add|list|remove."""

from __future__ import annotations

from pathlib import Path

import pytest

from key_amnesia.cli import main
from key_amnesia.logins import list_logins
from key_amnesia.prompt_route import AuthOutcome, PromptRequest


def _auth_ok(password: str):
    def fake(request: PromptRequest, *a, **k) -> AuthOutcome:
        return AuthOutcome(ok=True, route="inline", password=password)

    return fake


def _auth_deny(request: PromptRequest, *a, **k) -> AuthOutcome:
    return AuthOutcome(ok=False, route="inline", reason="cancelled")


def test_login_help() -> None:
    with pytest.raises(SystemExit) as ei:
        main(["login", "--help"])
    assert ei.value.code == 0


def test_login_add_help() -> None:
    with pytest.raises(SystemExit) as ei:
        main(["login", "add", "--help"])
    assert ei.value.code == 0


def test_login_list_help() -> None:
    with pytest.raises(SystemExit) as ei:
        main(["login", "list", "--help"])
    assert ei.value.code == 0


def test_login_remove_help() -> None:
    with pytest.raises(SystemExit) as ei:
        main(["login", "remove", "--help"])
    assert ei.value.code == 0


def test_login_without_subcommand() -> None:
    rc = main(["login"])
    assert rc == 2


def test_login_add_list_remove_roundtrip(
    seeded_vault: Path, password: str, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    monkeypatch.setattr(
        "key_amnesia.login_cli.require_human_auth",
        _auth_ok(password),
    )
    rc = main(
        ["login", "add", "https://example.com", "alice", "api_key"]
    )
    assert rc == 0
    out = capsys.readouterr()
    assert "alice" in out.err or "alice" in out.out

    rc = main(["login", "list"])
    assert rc == 0
    captured = capsys.readouterr()
    text = captured.out + captured.err
    assert "https://example.com\talice\tapi_key" in text
    assert "super-secret-value-123" not in text

    entries = list_logins(None, password)
    assert len(entries) == 1
    assert entries[0]["secret_name"] == "api_key"

    rc = main(["login", "remove", "https://example.com", "alice"])
    assert rc == 0
    assert list_logins(None, password) == []


def test_login_add_unknown_secret(
    seeded_vault: Path, password: str, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    monkeypatch.setattr(
        "key_amnesia.login_cli.require_human_auth",
        _auth_ok(password),
    )
    rc = main(
        ["login", "add", "https://example.com", "alice", "no_such_secret"]
    )
    assert rc == 1
    err = capsys.readouterr().err
    assert "unknown secret" in err.lower()


def test_login_fresh_auth_ignores_live_guard(
    seeded_vault: Path, password: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from key_amnesia import guard as guard_mod

    monkeypatch.setattr(guard_mod, "guard_is_alive", lambda *a, **k: True)
    calls = {"guard_request": 0}

    def fake_req(*a, **k):
        calls["guard_request"] += 1
        return {"ok": True}

    monkeypatch.setattr(guard_mod, "guard_request", fake_req)
    monkeypatch.setattr(
        "key_amnesia.login_cli.require_human_auth",
        _auth_ok(password),
    )

    assert main(["login", "list"]) == 0
    assert (
        main(
            ["login", "add", "https://example.com", "bob", "db_pass"]
        )
        == 0
    )
    assert main(["login", "remove", "https://example.com", "bob"]) == 0
    assert calls["guard_request"] == 0


def test_login_denied_without_auth(
    seeded_vault: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    monkeypatch.setattr(
        "key_amnesia.login_cli.require_human_auth",
        _auth_deny,
    )
    assert main(["login", "list"]) == 1
    assert (
        main(
            ["login", "add", "https://example.com", "alice", "api_key"]
        )
        == 1
    )
    assert main(["login", "remove", "https://example.com", "alice"]) == 1
    err = capsys.readouterr().err
    assert "Denied" in err


def test_login_list_empty(
    seeded_vault: Path, password: str, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    monkeypatch.setattr(
        "key_amnesia.login_cli.require_human_auth",
        _auth_ok(password),
    )
    rc = main(["login", "list"])
    assert rc == 0
    captured = capsys.readouterr()
    text = captured.out + captured.err
    assert "No login associations." in text
