# key-amnesia

**Let your AI agent *use* your passwords and API keys — without ever letting it *see* them.**

![key-amnesia — the vault hands the agent a sealed envelope it cannot open](media/assets/approved/readme-hero.png)

AI coding agents (Claude Code, Cursor, Codex) are incredibly useful — right up until they need an API key. Then your choices are ugly: paste the key into the chat (now it lives in the conversation forever), put it in a plain-text `.env` file the agent can read, or just do that part yourself.

**key-amnesia is the fourth option.** Your secrets live in an encrypted vault. The agent can *trigger* commands that use them — but the actual values are injected directly into the command's environment, out of the agent's sight. If a command tries to print a secret, key-amnesia censors it before the agent sees the output. And the master password can only ever be typed by you, a real human, at a real keyboard: when an agent needs your approval, a **separate console window pops up on your screen** — one the agent cannot read or type into.

The agent gets amnesia. That's the whole point. And every access attempt — allowed or denied — is written to an audit log you can review.

## How it works, in 30 seconds

```bash
# 1. Create the vault (type the master password twice to confirm)
ka init

# 2. Store a secret (you type it once, hidden, into a password prompt)
ka set OPENAI_API_KEY

# 3. The agent runs commands THROUGH key-amnesia instead of holding the key:
ka run --secret OPENAI_API_KEY --as OPENAI_API_KEY -- python my_script.py

# 4. That's it. The script gets the real key in its environment.
#    The agent sees the script's output — with any leaked key censored:
#    "Bearer ***REDACTED(OPENAI_API_KEY)***"
```

`ka init` asks for the master password twice; if the entries do not match, nothing is created. **There is no recovery** if you forget that password — Argon2id + SecretBox leave none by design.

When the agent triggers step 3 and your approval is needed, you'll see a new console window appear with a clear message — *"An agent-driven command is requesting: run with secret OPENAI_API_KEY"* — and only your password, typed there, lets it proceed. Close the window to deny. Nothing the agent controls can type into that window.

## Install

```bash
pip install git+https://github.com/fujitoid/key-amnesia
```

Or from a local clone: `pip install .` — either way you get both the full `key-amnesia` command and the short `ka` alias.

> Windows and Linux supported; macOS still falls back to fail-closed (not yet implemented).

### Browser fill — install

key-amnesia can act as the Native Messaging host that the [KeePassXC-Browser](https://keepassxc.org/docs/KeePassXC_GettingStarted.html#_setup_browser_integration) extension already talks to (`org.keepassxc.keepassxc_browser`). No separate extension is required.

```bash
# After pip install, register manifests for Chrome / Edge / Brave / Firefox:
ka browser-fill install

# Inspect what is registered (missing / ours / foreign):
ka browser-fill status

# Remove only key-amnesia's manifests:
ka browser-fill uninstall
```

**`ka unlock` is required** before the extension can retrieve logins. Browser-fill runs only while a cached unlock session is live; there is no per-call password path from the native host.

If a browser already has a host registered under that exact name (for example KeePassXC itself), install **warns and asks for confirmation** — or require `--force`. It never silently overwrites. Use `ka browser-fill status` to see `foreign(path=…)` entries before deciding.

Windows and Linux only; macOS install fails closed with a clear message.

## Two modes: ask every time, or unlock a session

| Mode | What it feels like |
|------|--------------------|
| **`per-call`** (default) | Every use of a secret asks for your password. Maximum safety, maximum prompts. |
| **`cached`** | You run `ka unlock` once in your terminal; a background "guard" keeps the vault open for 30 minutes (configurable). Agent commands run without prompts until it expires or you run `ka lock`. |

```bash
ka config set session-mode cached   # switch (asks for your password)
ka unlock                           # start a session
ka lock                             # end it early, any time
```

Before a session expires, the guard asks *in its own window* whether to extend. No answer means it locks itself.

## Commands

| Command | What it does |
|---------|--------------|
| `ka init` | Create an empty vault (type master password twice; refuse if already exists) |
| `ka set NAME` | Store or update a secret (value typed hidden; password required; vault must already exist) |
| `ka remove NAME` | Delete a secret (password required) |
| `ka run --secret NAME --as ENV_VAR -- <command>` | Run a command with the secret injected; output censored. The agent-facing command. |
| `ka list` | Show secret *names* only — never values; safe for agents, no prompt |
| `ka unlock` / `ka lock` | Start / end a cached session |
| `ka reveal NAME` | Show a value to *you* (password required every time, even mid-session) |
| `ka copy NAME` | Copy a value to your clipboard instead of showing it (same rule) |
| `ka login …` | Manage URL/username ↔ secret associations for browser fill — see [Managing logins](#managing-logins) |
| `ka config show` / `ka config set KEY VALUE` | View / change settings (changes require your password) |
| `ka status` | Is a session active, and until when |

Every command supports `--help`.

`reveal` and `copy` deserve a special note: even if an agent invokes them, the value appears **only in the pop-up window on your screen** (or your clipboard) — the agent's own process receives nothing but a status flag. And they *always* require a fresh password, session or no session — so an agent can never ride an open session into actually reading a value.

### Managing logins

Browser fill looks up which vault secret to use for a site via **login associations** — a URL, username, and existing secret name. Create and manage them only from the CLI (the extension's `set-login` path is stubbed in v2; the CLI is the only create path):

```text
ka login add <url> <username> <secret-name>
ka login list
ka login remove <url> <username>
```

Each of these always asks for your master password (fresh auth — never a cached session shortcut). `list` prints `url`, `username`, and `secret_name` only — never password values. The named secret must already exist (`ka set` it first) before you can `login add` it.

## Under the hood

For the security-curious — the full detail lives in [DESIGN.md](DESIGN.md):

- **Encryption:** the vault is a single file sealed with XSalsa20-Poly1305 (libsodium's SecretBox) under a key derived from your master password via Argon2id at its most expensive (`SENSITIVE`) setting — deliberately slow to brute-force, and deliberately never dialed down.
- **The routing rule:** any command needing your password checks whether it's running in a real terminal. Yes → asks right there. No (an agent invoked it) → spawns a fresh, isolated console window whose keyboard input can only come from you. No interactive session at all → fails closed, never falls back to something insecure.
- **The guard never hands out secrets.** In cached mode, the guard *itself* runs your command with the secret injected and returns only the censored output and exit code. Its protocol simply has no "give me the value" request — so even another process connecting to it directly can't ask for one.
- **Nothing sensitive on command lines.** Windows records process command lines in its audit logs (event 4688); key-amnesia passes all sensitive hand-off data between its own processes via environment variables instead.
- **Audit log:** `~/.key-amnesia/audit.log`, append-only JSON lines — timestamp, action, secret names (never values), route, allowed/denied/timeout.

Files live in `~/.key-amnesia/` (override: `KEY_AMNESIA_HOME`, `KEY_AMNESIA_VAULT_PATH`).

## Security limits — read this part honestly

No tool in this class can promise absolute secrecy, and we'd rather tell you exactly where the edges are:

1. **A command you run can still leak its own secret.** Censoring catches exact copies of the value in output — a command that base64-encodes or otherwise obfuscates the secret before printing slips through. This limit is shared by every tool of this kind (`op run`, `teller run`).
2. **Output is not live.** Command output is collected fully, censored, then released — the agent sees it only after the command finishes.
3. **Secret *names* are stored in plain text** (so `ka list` can work without a password). Values never are. Treat names as non-sensitive labels.
4. **The pop-up window assumes the agent can't control your screen.** If you've given an agent screen-reading *and* keyboard/mouse-injection powers, the window's isolation weakens — your typed password stays hidden, but a yes/no confirmation could theoretically be clicked by such an agent.
5. **Headless machines fail closed.** No display → no way to approve → the operation is denied. By design.
6. **Same-user processes share your privileges.** Any program running under your OS account can talk to a live guard session (this is equally true of `ssh-agent`). That's why the guard is designed to never return raw values — the worst a rogue same-user process gets is the same bounded "run a command" capability the legitimate path has.
7. **The master password never crosses any inter-process channel**, in any form — it's consumed only inside the process that prompted you for it.
8. **Avoid `ka set NAME VALUE` with the value inline.** It's supported for scripting, but an inline value briefly appears on the calling process's command line — visible to same-user process inspection and Windows command-line auditing. Prefer plain `ka set NAME` and type the value at the hidden prompt. (If an agent tries the inline form, the approval window shows you the incoming value before asking for your password — so you can still deny it.)

## CLI appearance

On a real terminal, status lines use a restrained brand palette (teal for info/success, amber for warnings, red only for hard denials). Set `NO_COLOR` or redirect output to a pipe/file and all ANSI escapes are omitted — agent-facing and scrubbed paths stay plain text. Glyphs fall back to ASCII (`[OK]` / `[DENIED]` / `[LOCKED]`) when color or unicode is unavailable. Scrubbed command output and raw revealed secret values are never styled.

## Development

```bash
pip install -e ".[dev]"
pytest
```

Design rationale, file formats, invariants: [DESIGN.md](DESIGN.md).

## License

Apache License 2.0 — see [LICENSE](LICENSE).
