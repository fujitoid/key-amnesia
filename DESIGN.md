# key-amnesia v3 — Design

Python prototype CLI (`key-amnesia` / `ka`) for Windows-primary use. Encrypted vault storage, Windows `CREATE_NEW_CONSOLE` human-prompt routing, a bounded-capability cached guard over named-pipe IPC (authkey only, plus an in-memory admission-consent layer), and buffer-then-scrub output redaction.

**0.3.0 cut:** browser-fill and the entire KeePassXC-Browser Native Messaging integration (`browser_fill.py`, `native_host.py`, `native_host_install.py`, `keepass_protocol.py`, `logins.py`, `login_cli.py`, `ka login`, `ka browser-fill`) are removed. `ka unlock` is no longer a detached child process — it *is* the guard, running in the caller's own foreground terminal. New: `ka passwd` / `ka change-password`, admission-consent prompting on the guard's own TTY, and honest death reporting (`last_guard_state.json`).

**0.3.1 (additive, no CLI-surface changes to `set`/`run`/`list`/`init`/`passwd`/`unlock`/`lock`/`status`/`renew`):** the three agent skills move from a root `skills/` copy into the installed package itself (`src/key_amnesia/skills/*/SKILL.md`, shipped as package data); a new blocking PreToolUse/preToolUse secret-guard hook module (`src/key_amnesia/hooks/secret_guard.py`, console script `key-amnesia-hook`) replaces the root `.claude/hooks/` copy; and a new non-interactive `ka setup` command (`src/key_amnesia/setup_cmd.py`) installs both into `~/.claude/` and `~/.cursor/` and merges each host's hook config idempotently.

**Out of scope:** macOS (and Safari); browser integration of any kind (removed, not deferred — see above); passkeys / TOTP; MCP wrapper; GUI; macOS isolated-console spawn (`Terminal.app` / `osascript`); DPAPI-protecting the names sidecar. Next iteration: Rust port of the same primitives (Argon2id, SecretBox AEAD, local IPC verbs).

---

## Package layout

```
key-amnesia/
  DESIGN.md
  README.md
  LICENSE                          # Apache 2.0
  .gitignore
  MANIFEST.in                      # ships skills/*/SKILL.md + hooks/*.py as package data
  pyproject.toml
  .claude/hooks/                   # pointer only — canonical hook now installed via `ka setup`
  skills/                          # pointer only — canonical skills now installed via `ka setup`
  src/key_amnesia/
    __init__.py
    __main__.py
    cli.py                         # argparse; all subcommands + --help
    paths.py
    config.py
    crypto.py                      # Argon2id + SecretBox (vault only)
    vault.py                       # binary layout + JSON payload; migrates obsolete fill keys
    scrub.py                       # exact substring replace, no regex
    audit.py                       # JSONL; never logs passwords
    ipc.py                         # Listener/Client + authkey only
    prompt_route.py                # isatty + CREATE_NEW_CONSOLE; env handoff
    guard.py                       # foreground singleton; admission consent; death reporting
    run_exec.py                    # buffer-then-scrub-then-relay
    clipboard.py
    theme.py                       # branded CLI output (NO_COLOR / non-TTY safe)
    platform.py                    # isolated-console spawn (Windows CREATE_NEW_CONSOLE; Linux emulators + /dev/tty install offer)
    setup_cmd.py                   # `ka setup`: installs skills + merges hook config into ~/.claude, ~/.cursor
    skills/                        # packaged agent skills (key-amnesia-usage / -hygiene / -migrate), package data
    hooks/
      secret_guard.py              # PreToolUse (Claude) / preToolUse (Cursor) blocking hook; console script key-amnesia-hook
  tests/
```

Entry points: `key-amnesia` and `ka` both → `key_amnesia.cli:main`; `key-amnesia-hook` → `key_amnesia.hooks.secret_guard:main`.

Deps: `pynacl`, `pyperclip`. Dev: `pytest`.

**Seams:** `theme.py` owns all branded local-console UX (respects `NO_COLOR` / non-TTY; scrubbed relays and raw reveal values stay unstyled). `platform.py` owns isolated-console spawn on Windows and Linux (macOS fail-closed).

---

## File formats

### Vault (`~/.key-amnesia/vault.bin`, override `KEY_AMNESIA_VAULT_PATH`)

```
magic[4]="KAM1" | version[1]=1 | salt[16] | opslimit[8] LE | memlimit[8] LE | SecretBox blob
```

Payload JSON:

```json
{
  "secrets": {"NAME": "value", ...},
  "created_at": "...",
  "updated_at": "..."
}
```

**Migration from pre-0.3.0 vaults:** older payloads may still carry `logins` / `browser_associations` / `database_id` from the removed browser-fill feature. `_normalize_payload` (in `vault.py`) drops all three on every `load_vault` / `save_vault`. If `logins` was a non-empty list, `load_vault` prints a one-time `theme.info` notice (`"Removed obsolete login associations - browser-fill was removed in 0.3.0."`); empty/absent keys are dropped silently. The save side never re-prints (a load-then-mutate-then-save round trip in the same command only warns once), but a save always persists the cleanup — a vault touched once under 0.3.0 has no legacy keys on disk from then on.

KDF: `argon2id.kdf` with **OPSLIMIT_SENSITIVE / MEMLIMIT_SENSITIVE only** (deliberate; never dial down). Dir `~/.key-amnesia/` with `0o700` on POSIX; Windows user-profile ACL defaults.

**Creation is explicit, not implicit.** `ka init` is the only path that creates a vault: it requires an interactive TTY (refuses non-interactively — vault creation is never routed through the spawned-console/agent flow at all, unlike every other privileged command), prompts for the master password **twice**, and only writes the vault if both entries match exactly; a mismatch aborts with nothing created. `ka set` refuses with a clear error (`"Vault not initialized. Run 'ka init' first."`) if no vault exists yet — it never creates one as a side effect. This replaced an earlier v0 gap where the first `ka set` call silently created the vault from a single, unconfirmed password entry (a typo there was permanent and undetectable until the next unlock attempt failed, with no recovery path since Argon2id + SecretBox provide none by design).

**Changing the master password.** `ka passwd` (alias `ka change-password`) re-encrypts the vault under a new password with a **fresh** Argon2id salt (`save_vault(..., salt=crypto.generate_salt())` — `save_vault` otherwise preserves the existing salt on a same-password re-save). TTY-only like `init` (never routed through the spawned-console helper — the master password never needs to leave this process either way). Refuses outright while a guard session is alive (`theme.error("Lock the vault first: ka lock")`) rather than letting the guard's in-memory key go stale mid-session.

### Names sidecar (prompt-free `list`)

Whole-vault AEAD cannot list names without the password. Sidecar `~/.key-amnesia/vault.names.json` = `{"names":[...]}` updated on every successful `set`/`remove`.

**Tradeoff:** secret *names* are plaintext at rest on disk; values never are. Acceptable to keep `list` agent-callable with no prompt. Future option (DPAPI-protect sidecar on Windows) remains out of scope.

### Config (`config.json`)

`session-mode` (default `per-call`), `session-timeout-minutes` (30), `prompt-timeout-seconds` (90).

### Guard lock (`guard.lock`)

`address` (named pipe), `authkey_hex`, `pid`, `expires_at`.

**No `session_key_hex`.** Authkey authentication alone defines the IPC trust boundary. An extra SecretBox layer over messages was dropped: with a session key co-stored in `guard.lock` next to the authkey, the same processes that can read the authkey can read the session key — zero added protection, pure complexity.

### Admission token (`admitted_session.token`)

Opaque `secrets.token_urlsafe(32)` string minted by the guard the first time it admits a client (see "Admission consent" below), cached on disk by the *client* side (`guard_request`) so subsequent CLI invocations in the same shell skip the prompt. Not a security boundary by itself (same-user readable, same trust tier as `guard.lock`) — it is a **UX/consent** layer on top of the authkey boundary, not a replacement for it. Cleared by the guard on `lock` / any teardown; a stale token from a previous guard run is simply unrecognized and re-prompts (harmless).

### Last guard state (`last_guard_state.json`)

Written by the guard on **every** exit path — `started_at`, `ended_at`, `reason` (`locked` / `expired` / `interrupted` / `crashed: <ExcType>`), `request_count`. Read by `format_no_guard_message()` so `ka lock` / `ka status` report what actually happened (`"Guard is not running. Last session ended 14:32 (expired after 30m, handled 4 requests)."`) instead of a bare "No active guard session."

### Audit (`audit.log` JSONL)

`timestamp`, `action`, `secret_names`, `command`, `route` (`inline`|`spawned-console`|`guard-session`), `result` (`allowed`|`denied`|`timeout`), `reason`. Never secret values, never passwords.

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

**`unlock` is the one action a spawned helper console cannot complete.** `ka unlock` blocks in the *caller's own terminal* for the life of the session — a separate spawned console is a different process with a different TTY, so it cannot become that guard on the parent's behalf. A non-interactive `unlock` still routes through the same isatty/spawn logic as every other command (so the routing decision, and its audit trail, stay uniform), but the helper's `unlock` handler refuses immediately with a clear reason (`"unlock must be run in a foreground terminal"`) instead of trying to start anything.

**Known limitation: `isatty()` is a heuristic, not a guarantee of an attentive human.** The routing above assumes a tty-shaped stdin means a real person is present to type a password inline. In practice a pseudo-terminal can exist with nobody actually watching it — observed with an AI coding agent whose own tool harness sometimes allocates a pty for a subprocess it invokes, unpredictably from the caller's side. When that happens, `key-amnesia` takes the inline branch and prints the prompt into a stream nobody reads. **Not fixed** (no reliable way to distinguish "tty-shaped" from "someone is actually there" from inside the process) — named honestly rather than silently left as a mystery. **What is fixed:** the consequence used to be an indefinite hang (`getpass`/`input` block forever with no timeout); inline password entry now runs on a `prompt-timeout-seconds`-bounded thread and fails closed with a clear "prompt timed out" outcome instead of hanging. The guard's own admission prompt (see below) uses the same bounded-thread pattern with a fixed 60s timeout.

### Nothing sensitive on argv — ever

Windows process-creation auditing (event 4688) and same-user process explorers record full command lines. Argv is an accidental persistence/exposure channel.

- Helper argv is **only** the bare subcommand: `key-amnesia _prompt-helper` (plus interpreter/module path as needed by the entry point).
- Pass request payload, authkey, reply address, parent PID, etc. via **environment variables** set on the `Popen` `env=` dict (not captured by 4688). Clear those env vars from the helper's view after reading if practical.
- Same rule everywhere else: no keys, no request JSON, no secret names, no secret values on any command line.

Helper behavior after env handoff:

- Prints clear UX, collects input, KDF/decrypts in-process.
- Watches parent PID / IPC disconnect → cancel and exit (no orphan window).
- Parent receives status-only replies — never password, never raw secrets.
- **Linux non-interactive spawn:** try `x-terminal-emulator`, then `gnome-terminal`, `konsole`, `xterm` (first on `PATH`). Headless (no `DISPLAY` / `WAYLAND_DISPLAY`), missing emulator, or spawn failure → fail closed. **macOS isolated-console spawn remains out of scope** (fail closed).

---

## Output scrubbing (buffer-then-scrub-then-relay)

**No streaming.** For every `run` path (CLI per-call, helper per-call, guard):

1. Collect the child's stdout and stderr **fully** as bytes (`communicate()` / equivalent).
2. Decode each stream once at the end.
3. Scrub each stream **independently**.
4. Scrub with **all** injected secret values (every name→value in the inject set), not just one.
5. Exact substring replacement only (`str.replace`-style). **Never** build a regex from the secret value.
6. Relay each scrubbed stream outward in one piece; return exit code.

Command output is **not live** — the agent sees it only after the command exits. Residual limit: deliberately obfuscated echoes (e.g. base64) still slip through.

---

## Foreground guard singleton + admission consent + honest death reporting (v3)

`ka unlock` **is** the guard. There is no detached child process, no `_guard` subcommand, and no bootstrap-env handoff (all present in v2, all removed). `run_foreground_guard(payload, timeout_minutes)`:

1. Builds `GuardState` (secrets only — no fill state, ever).
2. Starts one `multiprocessing.connection.Listener`, writes `guard.lock`.
3. Prints `"Guard listening (pid …, timeout …m). Waiting for requests..."` on the caller's own terminal.
4. Blocks in `guard_serve` until locked, expired, or interrupted.
5. On **every** exit path, writes `last_guard_state.json` with an honest reason before clearing `guard.lock`.

A second terminal's `ka unlock` still sees the live lock and soft-warns without starting a second guard (same singleton behavior as v2) — the singleton check is unchanged; only the guard's own execution model (foreground vs. detached-child) changed.

### Admission consent — a UX/consent layer above the authkey boundary

The guard's authkey remains the hard security boundary (same-user processes that know the authkey can talk to the guard — the ssh-agent-style limit, unchanged from v2). On top of that, v3 adds a lightweight **consent** layer: the first request from any client is gated by a yes/no prompt printed on the **guard's own foreground TTY** —

```
Session (pid {caller_pid}) wants: {short_summary}. Admit? [y/N]
```

— bounded by a 60s `threading.Thread` + `join` (same fail-closed pattern as the inline password prompt); timeout or any non-yes answer denies. On yes, the guard mints an opaque `secrets.token_urlsafe(32)` token, remembers it in-memory (`GuardState.admitted`), and returns it in the reply; the CLI's `guard_request` wrapper (used by every guard-talking command) persists it to `admitted_session.token` automatically. Once admitted, that token skips the prompt for the rest of *this* guard's lifetime — no re-prompting per command. A stale token from a previous guard run is simply unrecognized (re-prompts once, harmless).

`ka status` reports admission state (`admitted: yes/no`, `admitted_since`, `request_count`). The guard also logs one non-secret line per handled request on its own TTY (verb + allowed/denied) — a live activity feed for whoever is sitting at that terminal.

### Honest death reporting

Every guard exit path is wrapped and reported truthfully instead of a bare "no active session":

| Exit path | `last_guard_state.json` reason |
|---|---|
| Explicit `lock` verb (IPC) | `locked` |
| TTL reached | `expired` |
| `KeyboardInterrupt` (Ctrl+C) | `interrupted` — prints a one-line uptime/request-count/admitted summary on the guard's own TTY, then tears down the same way as `locked` |
| Any other exception | `crashed: <ExcType>` |

`format_no_guard_message()` (used by `cmd_lock` and `cmd_status`, and any future "no live guard" path) reads that file and produces e.g. `"Guard is not running. Last session ended 14:32 (expired after 30m, handled 4 requests)."` instead of a bare `"No active guard session."`

---

## Two-tier security model

1. **Hard guarantee (unchanged since v1):** the guard IPC never returns raw secrets; verbs stay exactly `{run, list, lock, status, renew}`. Automated regression asserts this dispatch set (`tests/test_guard_verbs_regression.py`).
2. **Admission consent (new in v3, described above)** is a UX/consent layer, not a second hard guarantee — it never weakens or replaces the authkey boundary, and it never gates *which* verbs exist, only *whether a first-time caller gets to use any of them* without a human noticing.

Browser-fill's "practical guarantee" / auth-precedent exception described in v2 no longer applies — that entire feature (and its narrowly-scoped cached-session read exception) is removed in 0.3.0.

---

## Who holds plaintext (invariant-critical)

| Path | Decryptor | Value use |
|------|-----------|-----------|
| Interactive per-call `run` | CLI | CLI injects env + spawns |
| Non-interactive per-call `run` | Helper | **Helper** spawns; returns scrubbed I/O + exit only |
| Cached `run` (live guard) | Guard | **Guard** spawns; IPC = scrubbed I/O + exit only |
| Interactive reveal/copy | CLI | Same console print/clipboard |
| Non-interactive reveal/copy | Helper | Show/copy **only in helper window**; caller gets status flag only |
| `ka passwd` | CLI (TTY-only) | Re-encrypts locally; never leaves this process |

Non-interactive per-call `run` makes the helper the one-shot decryptor and executor (bounded result shape, same as the guard path). Secrets are never handed back over IPC to the agent-invoked waiting process.

Guard IPC has **no** `get-value`/`reveal` verb. Same-user processes can talk to the guard (ssh-agent limit); damage is bounded to `run`/`list`/`lock`/session-control only, and now additionally requires at least one admitted consent prompt per guard lifetime.

---

## IPC

`multiprocessing.connection` on `\\.\pipe\key-amnesia-<random>` + `authkey` only. Messages are ordinary pickled/JSON objects over the authenticated connection — **no additional payload SecretBox**.

Guard verbs: `run`, `list`, `lock`, `status`, `renew` only. Every message additionally carries `caller_pid` (for the admission prompt's display text only — not a trust mechanism) and, once admitted, an `admission_token`.

Master password never appears on this channel in any form. Master password is never satisfiable non-interactively without a spawned console.

---

## Session modes

- **per-call (default):** no persistent guard; each privileged op goes through password routing; discard after use.
- **cached:** `unlock` runs the guard in the caller's own foreground terminal; timeout from unlock; ~2 min before expiry prompt extend on the guard's own TTY if still interactive; `lock` tears it down. Live guard → `run`/`list` skip the password prompt (first use per client still needs one admission consent prompt).

Always fresh master-password routing (never guard shortcut) for `reveal`, `copy`, `remove`, `config set`, `set`, and `passwd`.

---

## Commands

- `init` — creates the vault; TTY-only (no agent-triggered path), double-confirms the master password, refuses if a vault already exists
- `passwd` / `change-password` — re-encrypts the vault under a new password with a fresh salt; TTY-only; refuses while a guard session is alive
- `set` / `remove` — fresh auth; mutate vault + names index; `set` refuses if no vault exists yet rather than creating one implicitly
- `run --secret/--as ... -- cmd` — guard hit or per-call decrypt path; buffer-then-scrub child stdout/stderr → `***REDACTED(name)***`
- `list` — read names sidecar (no prompt); never values
- `unlock` — *is* the guard; blocks in the caller's own terminal until locked/expired/interrupted
- `lock` — tear down the live guard session (or report the last one's honest fate if none is live)
- `reveal` / `copy` — always fresh auth; display location follows TTY vs helper rule
- `config set session-mode|session-timeout-minutes` — always fresh auth
- `status` — live guard status (pid, expiry, secret count, admission state) or the last session's honest death report
- `setup` — non-interactive: copies the 3 packaged skills to `~/.claude/skills/` + `~/.cursor/skills/` and idempotently merges the secret-guard hook into `~/.claude/settings.json` (`PreToolUse`) + `~/.cursor/hooks.json` (`preToolUse`); `--skills-only` / `--hook-only` to do just one half; never mutates vault/session state
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

def guard_handle_message(msg: dict, state: GuardState, *, admit_prompt=None) -> dict: ...
def run_foreground_guard(payload: dict, timeout_minutes: int) -> int: ...
def format_no_guard_message() -> str: ...
```

---

## Guard never returns raw secret values

The guard and helper IPC replies expose only: status, scrubbed stdout/stderr, exit codes, secret *names*, and session metadata (including admission state). Never passwords. Never raw secret values.

---

## Testing

Vault round-trip / wrong password / tamper; obsolete browser-fill key migration on load (one-time notice only when `logins` was non-empty, silent drop otherwise, save-side persists the cleanup without a second notice) (`test_vault_migration.py`); `init` mismatch creates nothing, match creates an unlockable vault, refuses if a vault already exists; `set` refuses when no vault exists yet; `passwd` happy path re-encrypts with a fresh salt, refuses while guard alive, mismatch aborts, wrong current password aborts, TTY-only (`test_passwd_cmd.py`); scrubbing on both per-call and guard paths; crafted IPC client never gets raw values; guard verb set regression (`{run,list,lock,status,renew}` only, admission pre-seeded so verb dispatch itself is under test); cached-session `run` executes in the caller's cwd (threaded through the IPC message); admission-consent prompt approves/denies/times out, known token skips re-prompt, stale token from a different guard re-prompts, round-trips through `guard_request` end to end, `status` reports admission state (`test_guard_admission.py`); honest death reporting for `locked`/`expired`/`interrupted`/`crashed: <ExcType>`, `format_no_guard_message()` phrasing, guard prints its live status banner on start (`test_guard_death_reporting.py`); foreground unlock never spawns a subprocess, a spawned helper console refuses the `unlock` action with a clear reason instead of trying to start anything (`test_foreground_unlock.py`); argparse `--help` walk over the root parser and every subparser renders on a simulated cp1252 console without raising, automatically covers `setup` (`test_argparse_help_cp1252.py`); `isatty=False` asserts `CREATE_NEW_CONSOLE`, bare argv, env handoff; password never in IPC; inline password prompts fail closed on a bounded timeout instead of hanging when `isatty()` is fooled by a tty-shaped-but-unattended stream; reveal/copy non-interactive returns status only; helper parent-death cancels; unlock→run→lock→fallback; reveal/copy ignore live guard; config/remove/`set` need password; audit with no plaintext; `--help` (including `init`); scrubber uses replace not regex; Linux emulator selection order and env/argv handoff, immediate-exit fallthrough to the next emulator, headless and no-emulator fail-closed, macOS/other-platform fail-closed (`test_posix.py`); themed output respects `NO_COLOR` and non-TTY streams, ASCII glyph fallback, scrubbed/revealed values stay unstyled, degrades non-cp1252-encodable caller text instead of crashing (`test_theme.py`); secret-guard hook blocks every known prefix (OpenAI/Anthropic/AWS/GitHub/GitLab/Slack/Google/Stripe/npm) and high-entropy assignments, allows placeholder assignments (`PASSWORD=test123`), bare mentions, comments, and `ka run`/`ka set` command lines, host detection (Claude vs Cursor payload shape) picks the right deny contract, disable env skips everything, fails open on malformed/empty/non-dict stdin (`test_secret_guard.py`); `ka setup` copies all three skills to both hosts with matching content, overwrites stale copies on rerun, `--skills-only`/`--hook-only` isolate each half, Claude `settings.json` / Cursor `hooks.json` merges preserve unrelated keys and other hooks and are idempotent on rerun, malformed settings recover to a fresh merge, PATH check reports found/not-found via monkeypatched `shutil.which` (`test_setup_cmd.py`); a real wheel build (`pip wheel`) contains all three packaged `SKILL.md` files and the hook module (`test_package_skills_data.py`).
