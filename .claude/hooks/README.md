# Claude Code hooks — moved

The PreToolUse secret-guard hook is now packaged inside `key_amnesia` itself (`src/key_amnesia/hooks/secret_guard.py`) instead of living here as a separate root-level copy.

Install it (and the agent skills) with:

```bash
ka setup
```

This merges a `PreToolUse` entry into `~/.claude/settings.json` (and a `preToolUse` entry into `~/.cursor/hooks.json` for Cursor) that runs the `key-amnesia-hook` console script. There is now exactly one canonical copy of the hook (inside the installed package); this directory is a pointer only.
