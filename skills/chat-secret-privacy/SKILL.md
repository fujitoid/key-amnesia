---
name: chat-secret-privacy
description: >-
  Prevents echoing passwords, API keys, and tokens pasted into chat. Use when
  the user pastes a secret, shares credentials in a message, or asks to store
  or run something with a key. Offers ka set and prefers ka run for env injection.
---

# Chat secret privacy

When a user pastes a password, API key, token, or similar secret into chat, treat it as **sensitive material that must not be repeated**.

## Rules

1. **Stop echoing.** Do not repeat the secret in your reply, in tool args, in commits, or in files. Refer to it only by a short placeholder (e.g. `[redacted]`) or by the intended vault name.
2. **Offer `ka set`.** Suggest storing it in the key-amnesia vault so it never needs to live in the conversation again:
   ```bash
   ka set SECRET_NAME
   ```
   The human types the value at a hidden prompt — you do not need (and must not ask them to re-paste) the value in chat.
3. **Prefer `ka run`.** For any command that needs the secret, inject via env instead of inline:
   ```bash
   ka run --secret SECRET_NAME --as ENV_VAR -- <command>
   ```
   Never put the raw value on argv, in `.env` files the agent can read, or in shell history via `export SECRET=...`.
4. **Do not “helpfully” rewrite** the user’s paste into a script, curl header, or config with the value filled in. Point them at `ka set` + `ka run` instead.
5. If they already pasted a secret, acknowledge briefly that it should be rotated if the chat is retained, then move them to the vault flow — still without echoing the value.

## Out of scope

- Reading vault values (`reveal` / `copy`) — always human-prompted; agents must not chase raw values.
- General vault CLI usage — see `skills/using-key-amnesia/` when that skill is present.
