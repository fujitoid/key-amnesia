# key-amnesia v2 — Design

Python prototype CLI (`key-amnesia` / `ka`) for Windows-primary use. Encrypted vault storage, Windows `CREATE_NEW_CONSOLE` human-prompt routing, a bounded-capability cached guard over named-pipe IPC (authkey only), buffer-then-scrub output redaction, and KeePassXC-Browser Native Messaging fill (separate browser-fill IPC; guard verbs unchanged).

**Out of scope for v2:** macOS (and Safari); forking/modifying the KeePassXC-Browser extension; atomic fill+submit; passkeys / TOTP / create-new-group; extension-driven `set-login` (stubbed — CLI `ka login add` is the only create path); per-call / no-session browser-fill (hard-require `ka unlock`); MCP wrapper; GUI; macOS isolated-console spawn (`Terminal.app` / `osascript`); DPAPI-protecting the names sidecar. Next iteration: Rust port of the same primitives (Argon2id, SecretBox AEAD, local IPC verbs).

---

## Package layout

```
key-amnesia/
  DESIGN.md
  README.md
  LICENSE                          # Apache 2.0
  .gitignore
  pyproject.toml
  .claude/hooks/                   # PreToolUse secret hooks + install note
  skills/                          # using-key-amnesia + chat-secret-privacy agent skills
  src/key_amnesia/
    __init__.py
    __main__.py
    cli.py                         # argparse; all subcommands + --help
    paths.py
    config.py
    crypto.py                      # Argon2id + SecretBox (vault only)
    vault.py                       # binary layout + JSON payload
    scrub.py                       # exact substring replace, no regex
    audit.py                       # JSONL; browser-fill taxonomy never logs passwords
    ipc.py                         # Listener/Client + authkey only (guard + fill addresses)
    prompt_route.py                # isatty + CREATE_NEW_CONSOLE; env handoff; browser-fill-approve
    guard.py                       # verbs frozen; co-hosts fill Listener
    browser_fill.py                # second Listener; may return credentials after approval
    logins.py                      # encrypted login CRUD / URL host match
    login_cli.py                   # ka login … (WS-C)
    native_host.py                 # KeePassXC-Browser host entry (WS-A)
    native_host_install.py         # ka browser-fill install/status (WS-B)
    keepass_protocol.py            # NaCl box framing (WS-A)
    run_exec.py                    # buffer-then-scrub-then-relay
    clipboard.py
    theme.py                       # branded CLI output (NO_COLOR / non-TTY safe)
    platform.py                    # isolated-console spawn (Windows CREATE_NEW_CONSOLE; Linux terminal emulators)
  tests/
```

Entry points: `key-amnesia` and `ka` both → `key_amnesia.cli:main`; `key-amnesia-browser-host` → `key_amnesia.native_host:main`.

Deps: `pynacl`, `pyperclip`. Dev: `pytest`.

**Seams:** `theme.py` owns all branded local-console UX (respects `NO_COLOR` / non-TTY; scrubbed relays and raw reveal values stay unstyled). `platform.py` owns isolated-console spawn on Windows and Linux (macOS fail-closed).

---

## File formats

### Vault (`~/.key-amnesia/vault.bin`, override `KEY_AMNESIA_VAULT_PATH`)

```
magic[4]="KAM1" | version[1]=1 | salt[16] | opslimit[8] LE | memlimit[8] LE | SecretBox blob
```

Payload JSON (v2 additive fields default on load for older vaults):

```json
{
  "secrets": {"NAME": "value", ...},
  "logins": [{"url": "https://example.com", "username": "u", "secret_name": "NAME"}],
  "browser_associations": [{"id": "key-amnesia", "id_key_b64": "..."}],
  "database_id": "<stable hex>",
  "created_at": "...",
  "updated_at": "..."
}
```

Logins reference `secret_name` (no password duplication; no plaintext url/username sidecar). Domain match: equal hostnames, or `request_host.endswith("." + login_host)` (subdomain of stored host). Scheme/port ignored.

KDF: `argon2id.kdf` with **OPSLIMIT_SENSITIVE / MEMLIMIT_SENSITIVE only** (deliberate; never dial down). Dir `~/.key-amnesia/` with `0o700` on POSIX; Windows user-profile ACL defaults.

**Creation is explicit, not implicit.** `ka init` is the only path that creates a vault: it requires an interactive TTY (refuses non-interactively — vault creation is never routed through the spawned-console/agent flow at all, unlike every other privileged command), prompts for the master password **twice**, and only writes the vault if both entries match exactly; a mismatch aborts with nothing created. `ka set` refuses with a clear error (`"Vault not initialized. Run 'ka init' first."`) if no vault exists yet — it never creates one as a side effect. This replaced an earlier v0 gap where the first `ka set` call silently created the vault from a single, unconfirmed password entry (a typo there was permanent and undetectable until the next unlock attempt failed, with no recovery path since Argon2id + SecretBox provide none by design).

### Names sidecar (prompt-free `list`)

Whole-vault AEAD cannot list names without the password. Sidecar `~/.key-amnesia/vault.names.json` = `{"names":[...]}` updated on every successful `set`/`remove`.

**Tradeoff:** secret *names* are plaintext at rest on disk; values never are. Acceptable for v1 to keep `list` agent-callable with no prompt. Future option (DPAPI-protect sidecar on Windows) is explicitly out of scope for v1.

### Config (`config.json`)

`session-mode` (default `per-call`), `session-timeout-minutes` (30), `prompt-timeout-seconds` (90).

### Guard lock (`guard.lock`)

`address` (named pipe), `authkey_hex`, `pid`, `expires_at`.

**No `session_key_hex`.** Authkey authentication alone defines the IPC trust boundary. An extra SecretBox layer over messages was dropped: with a session key co-stored in `guard.lock` next to the authkey, the same processes that can read the authkey can read the session key — zero added protection, pure complexity.

### Browser-fill lock (`browser_fill.lock`)

Same shape as the guard lock (`address`, `authkey_hex`, `pid`, `expires_at`), distinct pipe/socket (`key-amnesia-fill-<hex>`). Authkey only. Started only as the second Listener inside the cached-mode guard child from `ka unlock`. `ka lock`, fill-IPC `lock`, and guard expiry tear down **both** listeners and delete **both** lock files — no residual fill window after lock/expiry.

### Audit (`audit.log` JSONL)

`timestamp`, `action`, `secret_names`, `command`, `route` (`inline`|`spawned-console`|`guard-session`), `result` (`allowed`|`denied`|`timeout`), `reason`. Never secret values.

Browser-fill actions: `browser-fill` / `browser-fill-denied` / `browser-fill-timeout`, with optional `url` (or host) and `username`. **Passwords must never appear in audit.log** (they may appear in the Native Messaging protocol response to the extension only).

---

## Console routing (central mechanism)

```
Needs human auth
  → stdin.isatty?
      yes → getpass/input inline → KDF decrypt in-process
      no  → spawn isolated console (bare argv, env handoff)
              → Windows: CREATE_NEW_CONSOLE
              → Linux: first of x-terminal-emulator / gnome-terminal / konsole / xterm
                (requires DISPLAY or WAYLAND_DISPLAY)
              → macOS / other / headless / no emulator → fail closed
              → parent waits on IPC (timeout 90s)
              → helper already did KDF locally; status-only reply
```

### Nothing sensitive on argv — ever

Windows process-creation auditing (event 4688) and same-user process explorers record full command lines. Argv is an accidental persistence/exposure channel.

- Helper argv is **only** the bare subcommand: `key-amnesia _prompt-helper` (plus interpreter/module path as needed by the entry point).
- Pass request payload, authkey, reply address, parent PID, etc. via **environment variables** set on the `Popen` `env=` dict (not captured by 4688). Clear those env vars from the helper’s view after reading if practical.
- Same rule everywhere else: no keys, no request JSON, no secret names, no secret values on any command line.

Helper behavior after env handoff:

- Prints clear UX, collects input, KDF/decrypts in-process.
- Watches parent PID / IPC disconnect → cancel and exit (no orphan window).
- Parent receives status-only replies — never password, never raw secrets.
- **Linux non-interactive spawn:** try `x-terminal-emulator`, then `gnome-terminal`, `konsole`, `xterm` (first on `PATH`). Headless (no `DISPLAY` / `WAYLAND_DISPLAY`), missing emulator, or spawn failure → fail closed. **macOS isolated-console spawn remains out of scope** (fail closed).

---

## Output scrubbing (buffer-then-scrub-then-relay)

**No streaming in v1.** For every `run` path (CLI per-call, helper per-call, guard):

1. Collect the child’s stdout and stderr **fully** as bytes (`communicate()` / equivalent).
2. Decode each stream once at the end.
3. Scrub each stream **independently**.
4. Scrub with **all** injected secret values (every name→value in the inject set), not just one.
5. Exact substring replacement only (`str.replace`-style). **Never** build a regex from the secret value.
6. Relay each scrubbed stream outward in one piece; return exit code.

Command output is **not live** — the agent sees it only after the command exits. Residual limit: deliberately obfuscated echoes (e..g. base64) still slip through.

---

## Two-tier security model (v2)

1. **Hard guarantee (unchanged):** the guard IPC never returns raw secrets; verbs stay exactly `{run, list, lock, status, renew}`. Automated regression asserts this dispatch set (`tests/test_guard_verbs_regression.py`).
2. **Practical guarantee (new):** after a **mandatory per-attempt human approval popup**, a raw password may be handed to the KeePassXC-Browser extension (an uncontrolled process) over Native Messaging. The value never returns to an agent-invoked CLI context. Residual risk: an adversarial same-browser DOM observer could read autofilled fields — same honest tone as the base64-scrubbing caveat in README.

**Auth precedent (call out by name):** browser-fill **reads** (`get-logins`) are **cached-session-eligible** — an explicit exception to the “always fresh auth” list, **narrowly scoped to reading an already-stored login**. The per-fill approval popup replaces the fresh-password gate **for that read only**. Vault **writes** (`ka set` / `ka login add|remove` / etc.) remain always-fresh-auth. Extension `set-login` is **not** in the exception (stubbed in v2 — return a clear protocol error; create logins only via CLI).

**`ka unlock` hard requirement:** fill listener starts only inside the cached-mode guard child. There is **no** per-call / no-session fill path in v2 (Native Messaging request/response cannot hold a browser call open through a full master-password KDF + `prompt-timeout-seconds` without racing extension host timeouts). When fill IPC is unreachable, the native host returns a protocol “database locked / unavailable” error — it does not spawn a password console.

**Host collision:** Native Messaging host name is fixed to `org.keepassxc.keepassxc_browser` (hardcoded by the extension). Only one active host for that name can exist per browser profile. If a foreign manifest already points elsewhere, install must warn and require confirm / `--force` — never silent overwrite.

---

## Who holds plaintext (invariant-critical)

| Path | Decryptor | Value use |
|------|-----------|-----------|
| Interactive per-call `run` | CLI | CLI injects env + spawns |
| Non-interactive per-call `run` | Helper | **Helper** spawns; returns scrubbed I/O + exit only |
| Cached `run` (live guard) | Guard | **Guard** spawns; IPC = scrubbed I/O + exit only |
| Interactive reveal/copy | CLI | Same console print/clipboard |
| Non-interactive reveal/copy | Helper | Show/copy **only in helper window**; caller gets status flag only |
| Browser fill `get-logins` (live unlock) | Guard child / fill Listener | After yes/no approval: credentials → native host → extension only |

Non-interactive per-call `run` makes the helper the one-shot decryptor and executor (bounded result shape, same as the guard path). Secrets are never handed back over IPC to the agent-invoked waiting process.

Guard IPC has **no** `get-value`/`reveal` verb. Same-user processes can talk to the guard (ssh-agent limit); damage is bounded to `run`/`list`/`lock`/session-control only. Browser-fill is a **separate** channel — not a sixth guard verb — and is the only path that may return passwords, and only to the native host after approval.

---

## IPC

`multiprocessing.connection` on `\\.\pipe\key-amnesia-<random>` + `authkey` only. Messages are ordinary pickled/JSON objects over the authenticated connection — **no additional payload SecretBox**. Fill uses a parallel address style (`key-amnesia-fill-<hex>`).

Guard verbs: `run`, `list`, `lock`, `status`, `renew` only.

Master password never appears on this channel in any form. Master password is never satisfiable non-interactively without a spawned console.

---

## Session modes

- **per-call (default):** no persistent guard; each privileged op goes through password routing; discard after use. Browser-fill is **unavailable** in this mode (no unlock session).
- **cached:** `unlock` starts guard holding decrypted vault **and** the browser-fill Listener; timeout from unlock; ~2 min before expiry prompt extend on guard’s TTY if still interactive; `lock` tears down both. Live guard → `run`/`list` skip prompt; live fill → `get-logins-for-url` after per-attempt approval.

Always fresh master-password routing (never guard shortcut) for `reveal`, `copy`, `remove`, `config set`, **`set`**, and **`login add` / `login list` / `login remove`**. Browser-fill **reads** are the named cached-session exception above (approval popup, not fresh password). Extension `set-login` remains stubbed — not cached-session-eligible.

---

## Commands

- `init` — creates the vault; TTY-only (no agent-triggered path), double-confirms the master password, refuses if a vault already exists
- `set` / `remove` — fresh auth; mutate vault + names index; `set` refuses if no vault exists yet rather than creating one implicitly
- `run --secret/--as ... -- cmd` — guard hit or per-call decrypt path; buffer-then-scrub child stdout/stderr → `***REDACTED(name)***`
- `list` — read names sidecar (no prompt); never values
- `unlock` / `lock` — cached session control
- `reveal` / `copy` — always fresh auth; display location follows TTY vs helper rule
- `login add <url> <username> <secret-name>` — fresh auth; associate an existing secret with a site/username (secret must already exist)
- `login list` — fresh auth; print url/username/secret_name only (never password values); no prompt-free sidecar
- `login remove <url> <username>` — fresh auth; drop that association
- Extension `set-login` is stubbed in v2 — CLI `login add` is the only create path
- `config set session-mode|session-timeout-minutes` — always fresh auth
- `_prompt-helper` — internal; bare argv + env handoff; omitted from top-level summary, still supports `--help`

---

## Core signatures

```python
def derive_key(password: bytes, salt: bytes, opslimit: int, memlimit: int) -> bytes: ...
def load_vault(path, password: str) -> dict: ...
def save_vault(path, password: str, payload: dict, *, salt=None) -> None: ...

def require_human_auth(request: PromptRequest, timeout_s: int) -> AuthOutcome: ...
def run_with_secrets(command: list[str], env_inject: dict[str, str],
                     secrets_by_name: dict[str, str], cwd=None) -> RunResult: ...
# RunResult: exit_code, scrubbed_stdout, scrubbed_stderr (after full buffer)

def scrub_text(text: str, secrets: dict[str, str]) -> str: ...
# exact str.replace for every value; no regex

def guard_handle_message(msg: dict, state: GuardState) -> dict: ...
```

---

## Guard never returns raw secret values

The guard and helper IPC replies expose only: status, scrubbed stdout/stderr, exit codes, secret *names*, and session metadata. Never passwords. Never raw secret values. Browser-fill is outside this channel: passwords may leave the fill Listener toward the native host only after approval, and must never be written to `audit.log`.

---

## Testing

Vault round-trip / wrong password / tamper; `init` mismatch creates nothing, match creates an unlockable vault, refuses if a vault already exists; `set` refuses when no vault exists yet; scrubbing on both per-call and guard paths; crafted IPC client never gets raw values; guard verb set regression (`{run,list,lock,status,renew}` only); fill lifecycle — `lock`/expiry kills fill IPC with no residual credential window; browser-fill audit actions never contain passwords; `isatty=False` asserts `CREATE_NEW_CONSOLE`, bare argv, env handoff; password never in IPC; reveal/copy non-interactive returns status only; helper parent-death cancels; unlock→run→lock→fallback; reveal/copy ignore live guard; config/remove/`set` need password; audit with no plaintext; `--help` (including `init`); scrubber uses replace not regex; Linux emulator selection order and env/argv handoff, immediate-exit fallthrough to the next emulator, headless and no-emulator fail-closed, macOS/other-platform fail-closed (`test_posix.py`); themed output respects `NO_COLOR` and non-TTY streams, ASCII glyph fallback, scrubbed/revealed values stay unstyled (`test_theme.py`).
