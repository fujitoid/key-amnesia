---
name: key-amnesia-usage
description: >-
  Use key-amnesia (`ka`) so agents can run commands with secrets without ever
  reading vault values. Check state first (`ka status` / `ka list`), then
  prefer `ka run --secret NAME --as NAME=ENVVAR -- ...`. Never paste keys into
  chat, argv, or files the agent can read. Use when needing API keys,
  passwords, env injection, vault secrets, or `ka`/`key-amnesia` commands.
---

# Using key-amnesia

key-amnesia lets you **use** secrets without **seeing** them. Values are injected into a child process environment; scrubbed output comes back. There is no MCP server and no agent path that returns raw vault values.

## State-first — never blanket init/unlock

Before doing anything, check what already exists:

```bash
ka status   # is a vault unlocked / a guard session live?
ka list     # what secret names exist (no password, no values)
```

Do **not** reflexively run `ka init` or `ka unlock` "just in case." `ka init` fails loudly if a vault already exists, and blindly unlocking starts a session the human didn't ask for. Only suggest `init`/`unlock` to the human when `status`/`list` show they're actually needed (see "Always human" below).

## Preferred pattern

```bash
ka run --secret NAME --as NAME=ENVVAR -- <command> [args...]
```

- `--as` takes **`NAME=ENVVAR`** (secret name on the left, target environment variable on the right) — this matches `_parse_as_mappings` in `cli.py` exactly. Getting the order backwards silently fails.
- Multiple secrets: repeat `--secret` / `--as` pairs as needed.
- Prefer discovering names with `ka list` before inventing them.
- Never embed a secret's actual value in a command you build for the agent to run — only ever reference it by *name* through `--secret`/`--as`.

## Safe for agents

| Action | OK? | Notes |
|--------|-----|-------|
| `ka status` | Yes | Session metadata only; check first |
| `ka list` | Yes | Names only; no password; never values |
| `ka run --secret NAME --as NAME=ENVVAR -- ...` | Yes | Primary agent path; may prompt the human |
| Reading vault files / inventing a `get-value` verb | **No** | Guard has no value-return verb |

## Always human (do not attempt, do not ask for pasted output)

These require a human at a real keyboard. When one of these is needed, **give the human the exact command to type themselves** — never attempt it yourself, and never ask the human to paste the result back into chat:

- **`ka init`** — human, TTY-only, double-confirms the master password. If no vault exists, tell the user to run `ka init` themselves.
- **`ka unlock`** — human starts a cached session in their own terminal. Don't run this speculatively; only suggest it if `ka status` shows no live session and the user wants fewer prompts.
- **`ka passwd`** (`ka change-password`) — human, TTY-only; changing the master password is never something an agent should trigger or attempt.
- **The admission prompt** — the first command sent to a live guard triggers a one-time yes/no prompt on the guard's own terminal. This is the human's approval, not yours; do not ask them to describe or paste what it said.
- `ka set NAME` — human-terminal only (see below); `ka reveal` / `ka copy` — value shown/copied for the human only, agent gets a status flag (see the hygiene skill for the full list).

## Anti-patterns

- Pasting secrets into chat or committing them to the repo
- Running `ka init` / `ka unlock` reflexively instead of checking `ka status`/`ka list` first
- Embedding a secret value inline in a command instead of using `--secret`/`--as`
- Calling `reveal`/`copy` to "check" a value for the agent, or asking the human to paste the result of a human-only command
- Assuming a live guard can return raw values over IPC — it cannot

## Human reference

Longer prose for operators: [docs/agent-usage.md](https://github.com/fujitoid/key-amnesia/blob/master/docs/agent-usage.md).
