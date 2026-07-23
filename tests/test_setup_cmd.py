"""`ka setup`: skills copy, hook config merge, PATH check."""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

import pytest

from key_amnesia import setup_cmd as sc
from key_amnesia.cli import main


def _ns(**kwargs) -> argparse.Namespace:
    defaults = {"skills_only": False, "hook_only": False}
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


@pytest.fixture
def fake_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(sc.Path, "home", staticmethod(lambda: home))
    return home


# --- skills land with correct content ---------------------------------------


def test_setup_copies_all_skills_to_both_hosts(fake_home: Path) -> None:
    rc = sc.cmd_setup(_ns())
    assert rc == 0
    for host_dir in ("claude", "cursor"):
        for name in sc.SKILL_NAMES:
            dest = fake_home / f".{host_dir}" / "skills" / name / "SKILL.md"
            assert dest.exists()
            content = dest.read_text(encoding="utf-8")
            assert content.startswith("---\nname: " + name)


def test_setup_skill_content_matches_package_source(fake_home: Path) -> None:
    sc.cmd_setup(_ns())
    from importlib import resources

    root = resources.files("key_amnesia") / "skills"
    for name in sc.SKILL_NAMES:
        expected = (root / name / "SKILL.md").read_text(encoding="utf-8")
        installed = (fake_home / ".claude" / "skills" / name / "SKILL.md").read_text(
            encoding="utf-8"
        )
        assert installed == expected


def test_setup_overwrites_on_rerun_with_stale_content(fake_home: Path) -> None:
    sc.cmd_setup(_ns())
    dest = fake_home / ".claude" / "skills" / sc.SKILL_NAMES[0] / "SKILL.md"
    dest.write_text("stale content that should be replaced", encoding="utf-8")

    sc.cmd_setup(_ns())
    assert dest.read_text(encoding="utf-8") != "stale content that should be replaced"


def test_setup_skills_only_skips_hook_files(fake_home: Path) -> None:
    sc.cmd_setup(_ns(skills_only=True))
    assert not (fake_home / ".claude" / "settings.json").exists()
    assert not (fake_home / ".cursor" / "hooks.json").exists()
    assert (fake_home / ".claude" / "skills" / sc.SKILL_NAMES[0] / "SKILL.md").exists()


def test_setup_hook_only_skips_skills(fake_home: Path) -> None:
    sc.cmd_setup(_ns(hook_only=True))
    assert not (fake_home / ".claude" / "skills").exists()
    assert not (fake_home / ".cursor" / "skills").exists()
    assert (fake_home / ".claude" / "settings.json").exists()
    assert (fake_home / ".cursor" / "hooks.json").exists()


def test_setup_rejects_both_only_flags(fake_home: Path, capsys) -> None:
    rc = sc.cmd_setup(_ns(skills_only=True, hook_only=True))
    assert rc == 2
    assert "mutually exclusive" in capsys.readouterr().err


# --- Claude settings.json merge ---------------------------------------------


def test_claude_settings_merge_preserves_unrelated_keys(fake_home: Path) -> None:
    path = fake_home / ".claude" / "settings.json"
    path.parent.mkdir(parents=True)
    path.write_text(
        json.dumps(
            {
                "some_other_setting": True,
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "Bash",
                            "hooks": [{"type": "command", "command": "some-other-hook"}],
                        }
                    ],
                    "PostToolUse": [{"matcher": "*", "hooks": []}],
                },
            }
        ),
        encoding="utf-8",
    )

    sc.cmd_setup(_ns(hook_only=True))

    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["some_other_setting"] is True
    assert "PostToolUse" in data["hooks"]
    matchers = [entry["matcher"] for entry in data["hooks"]["PreToolUse"]]
    assert "Bash" in matchers  # unrelated hook untouched
    commands = [
        h["command"]
        for entry in data["hooks"]["PreToolUse"]
        for h in entry["hooks"]
    ]
    assert "some-other-hook" in commands
    assert any("key-amnesia" in c or "secret_guard" in c for c in commands)


def test_claude_settings_merge_idempotent(fake_home: Path) -> None:
    sc.cmd_setup(_ns(hook_only=True))
    path = fake_home / ".claude" / "settings.json"
    first = json.loads(path.read_text(encoding="utf-8"))

    sc.cmd_setup(_ns(hook_only=True))
    second = json.loads(path.read_text(encoding="utf-8"))

    assert len(second["hooks"]["PreToolUse"]) == len(first["hooks"]["PreToolUse"]) == 1


def test_claude_settings_malformed_recovers_with_fresh_merge(fake_home: Path) -> None:
    path = fake_home / ".claude" / "settings.json"
    path.parent.mkdir(parents=True)
    path.write_text("{ not valid json !!", encoding="utf-8")

    rc = sc.cmd_setup(_ns(hook_only=True))
    assert rc == 0
    data = json.loads(path.read_text(encoding="utf-8"))
    assert len(data["hooks"]["PreToolUse"]) == 1


# --- Cursor hooks.json merge -------------------------------------------------


def test_cursor_hooks_merge_preserves_unrelated_entries(fake_home: Path) -> None:
    path = fake_home / ".cursor" / "hooks.json"
    path.parent.mkdir(parents=True)
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "hooks": {
                    "preToolUse": [{"command": "./other-hook.sh", "matcher": "Shell"}],
                    "afterFileEdit": [{"command": "./format.sh"}],
                },
            }
        ),
        encoding="utf-8",
    )

    sc.cmd_setup(_ns(hook_only=True))

    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["version"] == 1
    assert "afterFileEdit" in data["hooks"]
    commands = [e["command"] for e in data["hooks"]["preToolUse"]]
    assert "./other-hook.sh" in commands
    assert any("key-amnesia" in c or "secret_guard" in c for c in commands)


def test_cursor_hooks_merge_idempotent(fake_home: Path) -> None:
    sc.cmd_setup(_ns(hook_only=True))
    path = fake_home / ".cursor" / "hooks.json"
    first = json.loads(path.read_text(encoding="utf-8"))

    sc.cmd_setup(_ns(hook_only=True))
    second = json.loads(path.read_text(encoding="utf-8"))

    assert len(second["hooks"]["preToolUse"]) == len(first["hooks"]["preToolUse"]) == 1


def test_cursor_hooks_missing_file_creates_fresh(fake_home: Path) -> None:
    rc = sc.cmd_setup(_ns(hook_only=True))
    assert rc == 0
    path = fake_home / ".cursor" / "hooks.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["version"] == 1
    assert data["hooks"]["preToolUse"][0]["matcher"] == sc.CURSOR_MATCHER


def test_claude_hooks_matcher_is_bash_write_edit(fake_home: Path) -> None:
    sc.cmd_setup(_ns(hook_only=True))
    path = fake_home / ".claude" / "settings.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["hooks"]["PreToolUse"][0]["matcher"] == sc.CLAUDE_MATCHER


# --- PATH check --------------------------------------------------------------


def test_check_path_positive(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda name, path=None: f"/usr/bin/{name}" if name == "ka" else None)
    result = sc._check_path()
    assert "ka on PATH" in result


def test_check_path_negative(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda name, path=None: None)
    result = sc._check_path()
    assert "not found on PATH" in result


def test_check_path_falls_back_to_key_amnesia_name(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        shutil,
        "which",
        lambda name, path=None: "/usr/bin/key-amnesia" if name == "key-amnesia" else None,
    )
    result = sc._check_path()
    assert "ka on PATH" in result


# --- CLI wiring ---------------------------------------------------------------


def test_cli_setup_subcommand_registered(fake_home: Path) -> None:
    rc = main(["setup"])
    assert rc == 0
    assert (fake_home / ".claude" / "skills" / sc.SKILL_NAMES[0] / "SKILL.md").exists()


def test_cli_setup_flags_parsed(fake_home: Path) -> None:
    rc = main(["setup", "--skills-only"])
    assert rc == 0
    assert not (fake_home / ".claude" / "settings.json").exists()
