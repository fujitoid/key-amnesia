# Agent skills — moved

The `key-amnesia-usage`, `key-amnesia-hygiene`, and `key-amnesia-migrate` skills are now packaged inside `key_amnesia` itself (`src/key_amnesia/skills/*/SKILL.md`) instead of living here as a separate root-level copy.

Install them for Claude Code / Cursor with:

```bash
ka setup
```

This copies the current package version of each `SKILL.md` to `~/.claude/skills/` and `~/.cursor/skills/`. There is now exactly one canonical copy of each skill (inside the installed package); this directory is a pointer only.
