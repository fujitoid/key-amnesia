"""Phase 0 prompt + CLI seam smoke tests."""

from __future__ import annotations

import json

from key_amnesia.cli import main
from key_amnesia.prompt_route import PromptRequest, require_browser_fill_approval


def test_browser_fill_approve_inline_yes() -> None:
    req = PromptRequest(
        action="browser-fill-approve",
        secret_names=["api_key"],
        detail=json.dumps(
            {
                "url": "https://example.com",
                "usernames": ["alice"],
                "secret_names": ["api_key"],
            }
        ),
    )
    outcome = require_browser_fill_approval(
        req,
        isatty_fn=lambda: True,
        approve_provider=lambda: True,
    )
    assert outcome.ok is True
    assert outcome.password is None
    assert outcome.status_only and outcome.status_only.get("approved") is True


def test_browser_fill_approve_inline_no() -> None:
    req = PromptRequest(action="browser-fill-approve", detail='{"url":"https://x"}')
    outcome = require_browser_fill_approval(
        req,
        isatty_fn=lambda: True,
        approve_provider=lambda: False,
    )
    assert outcome.ok is False
    assert outcome.password is None
    assert outcome.status_only and outcome.status_only.get("approved") is False


def test_login_cli_wired(monkeypatch, password, seeded_vault, capsys) -> None:
    """login is implemented (WS-C); still requires fresh auth."""
    from key_amnesia.prompt_route import AuthOutcome

    monkeypatch.setattr(
        "key_amnesia.login_cli.require_human_auth",
        lambda *a, **k: AuthOutcome(ok=True, route="inline", password=password),
    )
    rc = main(["login", "list"])
    assert rc == 0
    captured = capsys.readouterr()
    assert "No login associations." in (captured.out + captured.err)


def test_browser_fill_cli_stub(capsys) -> None:
    rc = main(["browser-fill", "status"])
    assert rc == 1
    err = capsys.readouterr().err
    assert "not implemented" in err.lower() or "Phase 0" in err


def test_native_host_exits_cleanly_on_eof() -> None:
    """WS-A replaced the Phase 0 stub: empty stdin EOF → exit 0, no stub message."""
    import io

    from key_amnesia.native_host import run_host

    stdin = io.BytesIO()
    stdout = io.BytesIO()
    stderr = io.StringIO()
    rc = run_host(stdin=stdin, stdout=stdout, stderr=stderr)
    assert rc == 0
    assert stdout.getvalue() == b""
    assert "not implemented" not in stderr.getvalue().lower()
