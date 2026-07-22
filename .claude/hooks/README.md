# Claude Code hooks (key-amnesia)

PreToolUse guard that inspects pending **Bash** (and similar) tool commands for inline credential-shaped tokens — API key prefixes, `Bearer …`, and long high-entropy `SECRET=` / `TOKEN=` / `API_KEY=` assignments.

When a match is clear, the hook **denies** the tool call and tells the agent to use key-amnesia instead of pasting secrets:

```bash
ka set NAME
ka run --secret NAME --as ENV_VAR -- <command>
```

Commands that already invoke `ka run` / `ka set` (etc.) are left alone. On JSON parse or unexpected errors the hook **fails open** (exit 0, no decision) so a broken hook never bricks the agent.

## Install

Merge this into project `.claude/settings.json` (or your user `~/.claude/settings.json`):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "python \"${CLAUDE_PROJECT_DIR}/.claude/hooks/pre_tool_use_secrets.py\""
          }
        ]
      }
    ]
  }
}
```

Requirements: Python 3 on `PATH` (`python` or adjust the command to `python3`). No extra packages.

Optional: broaden the matcher to `Bash|Write|Edit` if you also want Write/Edit payloads scanned.

## Pair with skills

- `skills/chat-secret-privacy/` — stop echoing secrets pasted in chat; offer `ka set` / prefer `ka run`
- `skills/using-key-amnesia/` — general agent usage patterns for the vault CLI
