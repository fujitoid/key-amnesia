"""PreToolUse/preToolUse secret-guard hook: detection + host deny contracts."""

from __future__ import annotations

import io
import json

import pytest

from key_amnesia.hooks import secret_guard as sg


# --- true positives: known prefixes -----------------------------------------

KNOWN_PREFIX_SAMPLES = [
    ("sk-" + "a" * 25, "OpenAI-style key"),
    ("sk-ant-" + "a" * 25, "Anthropic-style key"),
    ("AKIA" + "0" * 16, "AWS access key id"),
    ("ghp_" + "a" * 25, "GitHub PAT"),
    ("github_pat_" + "a" * 25, "GitHub fine-grained PAT"),
    ("glpat-" + "a" * 25, "GitLab PAT"),
    ("xoxb-" + "a" * 25, "Slack token"),
    ("AIza" + "a" * 25, "Google API key"),
    ("sk_live_" + "a" * 25, "Stripe secret key"),
    ("rk_live_" + "a" * 25, "Stripe restricted key"),
    ("npm_" + "a" * 25, "npm token"),
]


@pytest.mark.parametrize("token,expected_kind", KNOWN_PREFIX_SAMPLES)
def test_known_prefixes_block(token: str, expected_kind: str) -> None:
    text = f"curl -H 'Authorization: {token}' https://example.com"
    assert sg.find_finding(text) == expected_kind


def test_bearer_token_blocks() -> None:
    text = "curl -H 'Authorization: Bearer abcdEFGH12345678ijkl' https://example.com"
    assert sg.find_finding(text) == "Bearer token"


def test_high_entropy_assignment_blocks() -> None:
    text = "export API_KEY=aB3xQ9mK2pL7vN4wZ8"
    finding = sg.find_finding(text)
    assert finding is not None
    assert "assignment" in finding


def test_high_entropy_assignment_blocks_quoted() -> None:
    text = 'TOKEN="Zk9pL2xQ7mN4vB8w"'
    assert sg.find_finding(text) is not None


# --- false positives (advisory-safe / must not block) -----------------------


def test_password_placeholder_allowed() -> None:
    assert sg.find_finding("PASSWORD=test123") is None


def test_bare_api_key_mention_allowed() -> None:
    assert sg.find_finding("echo API_KEY is required") is None


def test_comment_mentioning_secret_allowed() -> None:
    assert sg.find_finding("# this function handles the secret rotation") is None


def test_changeme_placeholder_allowed() -> None:
    assert sg.find_finding("TOKEN=changeme") is None


def test_ka_run_command_allowed_even_with_secret_name() -> None:
    text = "ka run --secret API_KEY --as API_KEY=API_KEY -- python app.py"
    assert sg.find_finding(text) is None


def test_ka_set_command_allowed() -> None:
    assert sg.find_finding("ka set OPENAI_API_KEY") is None


def test_empty_text_allowed() -> None:
    assert sg.find_finding("") is None


# --- host detection + deny shapes -------------------------------------------


def test_detect_host_claude_default() -> None:
    payload = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {}}
    assert sg.detect_host(payload) == "claude"


def test_detect_host_cursor_by_event_name() -> None:
    payload = {"hook_event_name": "preToolUse", "tool_name": "Shell", "tool_input": {}}
    assert sg.detect_host(payload) == "cursor"


def test_detect_host_cursor_by_unique_fields() -> None:
    payload = {
        "conversation_id": "abc",
        "cursor_version": "1.7.2",
        "tool_name": "Shell",
        "tool_input": {},
    }
    assert sg.detect_host(payload) == "cursor"


def test_deny_claude_shape() -> None:
    reply = sg.deny_claude("OpenAI-style key")
    hso = reply["hookSpecificOutput"]
    assert hso["hookEventName"] == "PreToolUse"
    assert hso["permissionDecision"] == "deny"
    assert "ka set" in hso["permissionDecisionReason"]
    assert "ka run" in hso["permissionDecisionReason"]


def test_deny_cursor_shape() -> None:
    reply = sg.deny_cursor("OpenAI-style key")
    assert reply["permission"] == "deny"
    assert "agent_message" in reply
    assert "user_message" in reply
    assert "ka set" in reply["agent_message"] or "ka run" in reply["agent_message"]


# --- main() end-to-end (stdin JSON -> stdout JSON) --------------------------


def _run_main(payload: dict, monkeypatch: pytest.MonkeyPatch, capsys) -> tuple[int, dict | None]:
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(payload)))
    rc = sg.main()
    out = capsys.readouterr().out.strip()
    return rc, (json.loads(out) if out else None)


def test_main_claude_bash_blocks(monkeypatch, capsys) -> None:
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "export TOKEN=" + "sk-" + "a" * 25},
    }
    rc, reply = _run_main(payload, monkeypatch, capsys)
    assert rc == 0
    assert reply is not None
    assert reply["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_main_cursor_shell_blocks(monkeypatch, capsys) -> None:
    payload = {
        "hook_event_name": "preToolUse",
        "cursor_version": "1.7.2",
        "conversation_id": "abc",
        "tool_name": "Shell",
        "tool_input": {"command": "export TOKEN=" + "sk-" + "a" * 25},
    }
    rc, reply = _run_main(payload, monkeypatch, capsys)
    assert rc == 0
    assert reply is not None
    assert reply["permission"] == "deny"


def test_main_write_tool_scans_contents(monkeypatch, capsys) -> None:
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {"file_path": "x.env", "contents": "AKIA" + "0" * 16},
    }
    rc, reply = _run_main(payload, monkeypatch, capsys)
    assert rc == 0
    assert reply is not None


def test_main_clean_command_allows(monkeypatch, capsys) -> None:
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "echo hello world"},
    }
    rc, reply = _run_main(payload, monkeypatch, capsys)
    assert rc == 0
    assert reply is None


def test_main_ignores_unmatched_tool(monkeypatch, capsys) -> None:
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"command": "sk-" + "a" * 25},
    }
    rc, reply = _run_main(payload, monkeypatch, capsys)
    assert rc == 0
    assert reply is None


def test_main_disable_env_skips_everything(monkeypatch, capsys) -> None:
    monkeypatch.setenv(sg.DISABLE_ENV, "1")
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "export TOKEN=" + "sk-" + "a" * 25},
    }
    rc, reply = _run_main(payload, monkeypatch, capsys)
    assert rc == 0
    assert reply is None


def test_main_fails_open_on_malformed_json(monkeypatch, capsys) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO("not json{{{"))
    rc = sg.main()
    out = capsys.readouterr().out
    assert rc == 0
    assert out == ""


def test_main_fails_open_on_empty_stdin(monkeypatch, capsys) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    rc = sg.main()
    out = capsys.readouterr().out
    assert rc == 0
    assert out == ""


def test_main_fails_open_on_non_dict_json(monkeypatch, capsys) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(["not", "a", "dict"])))
    rc = sg.main()
    out = capsys.readouterr().out
    assert rc == 0
    assert out == ""
