---
name: using-key-amnesia
description: >-
  Use key-amnesia (`ka`) so agents can run commands with secrets without ever
  reading vault values. Prefer `ka run --secret/--as`; use `ka list` for names
  only. Never paste keys into chat, argv, or files the agent can read. Use when
  needing API keys, passwords, env injection, vault secrets, or `ka`/`key-amnesia`
  commands.
---

# Using key-amnesia

key-amnesia lets you **use** secrets without **seeing** them. Values are injected into a child process environment; scrubbed output comes back. There is no MCP server and no agent path that returns raw vault values.

## Preferred pattern

```bash
ka run --secret NAME --as ENV_VAR -- <command> [args...]
```

- Inject secrets only via `--secret` / `--as`. Never paste keys into chat, scripts, `.env`, or command argv.
- Multiple secrets: repeat `--secret` / `--as` pairs as needed.
- Prefer discovering names with `ka list` before inventing them.

## Safe for agents

| Action | OK? | Notes |
|--------|-----|-------|
| `ka run --secret … --as … -- …` | Yes | Primary agent path; may prompt the human |
| `ka list` | Yes | Names only; no password; never values |
| `ka status` | Yes | Session metadata only |
| `ka unlock` / `ka lock` | Human | Cached-session control; human TTY / approval |
| Reading vault files / inventing `get-value` | **No** | Guard has no value-return verb |

## Always human (do not rely on agent automation)

These always require a fresh human password prompt (or fail closed). A **cached session does not unlock** them:

- `ka reveal NAME` — value shown only to the human (TTY or helper window); agent gets status only
- `ka copy NAME` — clipboard for the human only; same rule
- `ka remove NAME`
- `ka config set …`
- `ka set NAME` — prefer interactive value entry; avoid `ka set NAME VALUE` (value briefly on argv)

**`ka init`** is human **TTY-only**: double-confirm master password; never route through agent/spawned-console flows. If no vault exists, tell the user to run `ka init` themselves — do not attempt it non-interactively.

## Cached session caveat

`ka unlock` (with `session-mode cached`) lets subsequent `ka run` / `ka list` skip prompts until timeout or `ka lock`. It does **not** authorize `reveal` or `copy`. Never treat an open session as permission to surface secret values.

## Anti-patterns

- Pasting secrets into chat or committing them to the repo
- Running tools that print env/secrets and expecting to "just look"
- Calling `reveal`/`copy` to "check" a value for the agent
- Creating the vault via agent-driven `init`
- Assuming a live guard can return raw values over IPC — it cannot

## Human reference

Longer prose for operators: [docs/agent-usage.md](../../docs/agent-usage.md).
