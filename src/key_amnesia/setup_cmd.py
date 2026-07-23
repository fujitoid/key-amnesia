"""`ka setup`: non-interactive install of packaged skills + secret-guard hook.

Copies the three bundled agent skills to the Claude Code / Cursor skills
directories and merges a `PreToolUse` (Claude) / `preToolUse` (Cursor) hook
entry into each host's own config file. Safe to re-run (idempotent upsert);
never drops unrelated keys or other hooks/matchers already present.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from importlib import resources
from pathlib import Path

from key_amnesia import theme

SKILL_NAMES = ["key-amnesia-usage", "key-amnesia-hygiene", "key-amnesia-migrate"]

CLAUDE_MATCHER = "Bash|Write|Edit"
CURSOR_MATCHER = "Shell|Write"
HOOK_COMMAND = "key-amnesia-hook"
HOOK_COMMAND_FALLBACK = "python -m key_amnesia.hooks.secret_guard"


def _skills_root():
    return resources.files("key_amnesia") / "skills"


def _copy_skills(dest_roots: list[Path]) -> list[str]:
    lines: list[str] = []
    root = _skills_root()
    for name in SKILL_NAMES:
        src = root / name / "SKILL.md"
        content = src.read_text(encoding="utf-8")
        for dest_root in dest_roots:
            dest_dir = dest_root / name
            dest_dir.mkdir(parents=True, exist_ok=True)
            dest_file = dest_dir / "SKILL.md"
            dest_file.write_text(content, encoding="utf-8")
            lines.append(f"skill updated: {name} -> {dest_file}")
    return lines


def _load_json_object(path: Path) -> dict:
    """Read existing JSON as a dict; recover to `{}` on missing/malformed input."""
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def _hook_command() -> str:
    return HOOK_COMMAND if shutil.which(HOOK_COMMAND) else HOOK_COMMAND_FALLBACK


def _is_our_hook_command(command: str) -> bool:
    return "key-amnesia-hook" in command or "key_amnesia.hooks.secret_guard" in command


def _merge_claude_settings(path: Path) -> None:
    settings = _load_json_object(path)
    hooks = settings.get("hooks")
    if not isinstance(hooks, dict):
        hooks = {}
    settings["hooks"] = hooks

    pretooluse = hooks.get("PreToolUse")
    if not isinstance(pretooluse, list):
        pretooluse = []

    def _is_ours(entry: object) -> bool:
        if not isinstance(entry, dict):
            return False
        for hook in entry.get("hooks", []) or []:
            if isinstance(hook, dict) and _is_our_hook_command(str(hook.get("command") or "")):
                return True
        return False

    kept = [e for e in pretooluse if not _is_ours(e)]
    kept.append(
        {
            "matcher": CLAUDE_MATCHER,
            "hooks": [{"type": "command", "command": _hook_command()}],
        }
    )
    hooks["PreToolUse"] = kept
    _write_json(path, settings)


def _merge_cursor_hooks(path: Path) -> None:
    settings = _load_json_object(path)
    settings.setdefault("version", 1)
    hooks = settings.get("hooks")
    if not isinstance(hooks, dict):
        hooks = {}
    settings["hooks"] = hooks

    pretooluse = hooks.get("preToolUse")
    if not isinstance(pretooluse, list):
        pretooluse = []

    def _is_ours(entry: object) -> bool:
        return isinstance(entry, dict) and _is_our_hook_command(str(entry.get("command") or ""))

    kept = [e for e in pretooluse if not _is_ours(e)]
    kept.append({"command": _hook_command(), "matcher": CURSOR_MATCHER})
    hooks["preToolUse"] = kept
    _write_json(path, settings)


def _path_guidance() -> str:
    if sys.platform == "win32":
        scripts_dir = Path(sys.executable).parent / "Scripts"
        return (
            "`ka` was not found on PATH. If you installed with `pip install --user`, "
            f"add its Scripts directory to PATH: {scripts_dir}"
        )
    return (
        "`ka` was not found on PATH. If you installed with `pip install --user`, "
        "add ~/.local/bin to PATH (e.g. in your ~/.bashrc or ~/.zshrc), then "
        "restart your shell."
    )


def _check_path() -> str:
    fresh_path = os.environ.get("PATH")
    found = shutil.which("ka", path=fresh_path) or shutil.which("key-amnesia", path=fresh_path)
    if found:
        return f"ka on PATH: {found}"
    return _path_guidance()


def cmd_setup(args: argparse.Namespace) -> int:
    skills_only = bool(getattr(args, "skills_only", False))
    hook_only = bool(getattr(args, "hook_only", False))
    if skills_only and hook_only:
        theme.error("--skills-only and --hook-only are mutually exclusive.")
        return 2

    home = Path.home()
    lines: list[str] = []

    if not hook_only:
        dest_roots = [home / ".claude" / "skills", home / ".cursor" / "skills"]
        lines.extend(_copy_skills(dest_roots))

    if not skills_only:
        claude_settings = home / ".claude" / "settings.json"
        cursor_hooks = home / ".cursor" / "hooks.json"
        _merge_claude_settings(claude_settings)
        lines.append(f"hook installed: {claude_settings} (PreToolUse)")
        _merge_cursor_hooks(cursor_hooks)
        lines.append(f"hook installed: {cursor_hooks} (preToolUse)")

    lines.append(_check_path())

    for line in lines:
        theme.out(line)

    theme.info(
        "Restart Claude Code / Cursor (or reload the window) to pick up the "
        "new skills and hook."
    )
    theme.info(
        "In your own terminal: `ka init` (first time) or `ka unlock` (start a session)."
    )
    return 0
