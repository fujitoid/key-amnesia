# key-amnesia v0 — Design

Python prototype CLI (`key-amnesia` / `ka`) for Windows-primary use. Encrypted vault storage, Windows `CREATE_NEW_CONSOLE` human-prompt routing, a bounded-capability cached guard over named-pipe IPC (authkey only), and buffer-then-scrub output redaction.

**Out of scope for v0:** browser injection, MCP wrapper, GUI, POSIX terminal-spawn equivalent, DPAPI-protecting the names sidecar. Next iteration: Rust port of the same primitives (Argon2id, SecretBox AEAD, local IPC verbs).

---

## Package layout

```
key-amnesia/
  DESIGN.md
  README.md
  LICENSE                          # Apache 2.0
  .gitignore
  pyproject.toml
  src/key_amnesia/
    __init__.py
    __main__.py
    cli.py                         # argparse; all subcommands + --help
    paths.py
    config.py
    crypto.py                      # Argon2id + SecretBox (vault only)
    vault.py                       # binary layout + JSON payload
    scrub.py                       # exact substring replace, no regex
    audit.py
    ipc.py                         # Listener/Client + authkey only
    prompt_route.py                # isatty + CREATE_NEW_CONSOLE; env handoff
    guard.py
    run_exec.py                    # buffer-then-scrub-then-relay
    clipboard.py
  tests/
```

Entry points: `key-amnesia` and `ka` both → `key_amnesia.cli:main`.

Deps: `pynacl`, `pyperclip`. Dev: `pytest`.

---

## File formats

### Vault (`~/.key-amnesia/vault.bin`, override `KEY_AMNESIA_VAULT_PATH`)

```
magic[4]="KAM1" | version[1]=1 | salt[16] | opslimit[8] LE | memlimit[8] LE | SecretBox blob
```

Payload JSON: `{"secrets": {...}, "created_at": "...", "updated_at": "..."}`.

KDF: `argon2id.kdf` with **OPSLIMIT_SENSITIVE / MEMLIMIT_SENSITIVE only** (deliberate; never dial down). Dir `~/.key-amnesia/` with `0o700` on POSIX; Windows user-profile ACL defaults.

**Creation is explicit, not implicit.** `ka init` is the only path that creates a vault: it requires an interactive TTY (refuses non-interactively — vault creation is never routed through the spawned-console/agent flow at all, unlike every other privileged command), prompts for the master password **twice**, and only writes the vault if both entries match exactly; a mismatch aborts with nothing created. `ka set` refuses with a clear error (`"Vault not initialized. Run 'ka init' first."`) if no vault exists yet — it never creates one as a side effect. This replaced an earlier v0 gap where the first `ka set` call silently created the vault from a single, unconfirmed password entry (a typo there was permanent and undetectable until the next unlock attempt failed, with no recovery path since Argon2id + SecretBox provide none by design).

### Names sidecar (prompt-free `list`)

Whole-vault AEAD cannot list names without the password. Sidecar `~/.key-amnesia/vault.names.json` = `{"names":[...]}` updated on every successful `set`/`remove`.

**Tradeoff:** secret *names* are plaintext at rest on disk; values never are. Acceptable for v0 to keep `list` agent-callable with no prompt. Future option (DPAPI-protect sidecar on Windows) is explicitly out of scope for v0.

### Config (`config.json`)

`session-mode` (default `per-call`), `session-timeout-minutes` (30), `prompt-timeout-seconds` (90).

### Guard lock (`guard.lock`)

`address` (named pipe), `authkey_hex`, `pid`, `expires_at`.

**No `session_key_hex`.** Authkey authentication alone defines the IPC trust boundary. An extra SecretBox layer over messages was dropped: with a session key co-stored in `guard.lock` next to the authkey, the same processes that can read the authkey can read the session key — zero added protection, pure complexity.

### Audit (`audit.log` JSONL)

`timestamp`, `action`, `secret_names`, `command`, `route` (`inline`|`spawned-console`|`guard-session`), `result` (`allowed`|`denied`|`timeout`), `reason`. Never secret values.

---

## Console routing (central mechanism)

```
Needs human auth
  → stdin.isatty?
      yes → getpass/input inline → KDF decrypt in-process
      no  → Popen helper CREATE_NEW_CONSOLE (bare argv, env handoff)
              → console ok? no → fail closed
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
- **POSIX non-interactive spawn: out of scope for v0; fail closed / unsupported.**

---

## Output scrubbing (buffer-then-scrub-then-relay)

**No streaming in v0.** For every `run` path (CLI per-call, helper per-call, guard):

1. Collect the child’s stdout and stderr **fully** as bytes (`communicate()` / equivalent).
2. Decode each stream once at the end.
3. Scrub each stream **independently**.
4. Scrub with **all** injected secret values (every name→value in the inject set), not just one.
5. Exact substring replacement only (`str.replace`-style). **Never** build a regex from the secret value.
6. Relay each scrubbed stream outward in one piece; return exit code.

Command output is **not live** — the agent sees it only after the command exits. Residual limit: deliberately obfuscated echoes (e..g. base64) still slip through.

---

## Who holds plaintext (invariant-critical)

| Path | Decryptor | Value use |
|------|-----------|-----------|
| Interactive per-call `run` | CLI | CLI injects env + spawns |
| Non-interactive per-call `run` | Helper | **Helper** spawns; returns scrubbed I/O + exit only |
| Cached `run` (live guard) | Guard | **Guard** spawns; IPC = scrubbed I/O + exit only |
| Interactive reveal/copy | CLI | Same console print/clipboard |
| Non-interactive reveal/copy | Helper | Show/copy **only in helper window**; caller gets status flag only |

Non-interactive per-call `run` makes the helper the one-shot decryptor and executor (bounded result shape, same as the guard path). Secrets are never handed back over IPC to the agent-invoked waiting process.

Guard IPC has **no** `get-value`/`reveal` verb. Same-user processes can talk to the guard (ssh-agent limit); damage is bounded to `run`/`list`/`lock`/session-control only.

---

## IPC

`multiprocessing.connection` on `\\.\pipe\key-amnesia-<random>` + `authkey` only. Messages are ordinary pickled/JSON objects over the authenticated connection — **no additional payload SecretBox**.

Guard verbs: `run`, `list`, `lock`, `status`, `renew` only.

Master password never appears on this channel in any form. Master password is never satisfiable non-interactively without a spawned console.

---

## Session modes

- **per-call (default):** no persistent guard; each privileged op goes through password routing; discard after use.
- **cached:** `unlock` starts guard holding decrypted vault; timeout from unlock; ~2 min before expiry prompt extend on guard’s TTY if still interactive; `lock` tears down. Live guard → `run`/`list` skip prompt.

Always fresh master-password routing (never guard shortcut) for `reveal`, `copy`, `remove`, `config set`, and **`set`**.

---

## Commands

- `init` — creates the vault; TTY-only (no agent-triggered path), double-confirms the master password, refuses if a vault already exists
- `set` / `remove` — fresh auth; mutate vault + names index; `set` refuses if no vault exists yet rather than creating one implicitly
- `run --secret/--as ... -- cmd` — guard hit or per-call decrypt path; buffer-then-scrub child stdout/stderr → `***REDACTED(name)***`
- `list` — read names sidecar (no prompt); never values
- `unlock` / `lock` — cached session control
- `reveal` / `copy` — always fresh auth; display location follows TTY vs helper rule
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

The guard and helper IPC replies expose only: status, scrubbed stdout/stderr, exit codes, secret *names*, and session metadata. Never passwords. Never raw secret values.

---

## Testing

Vault round-trip / wrong password / tamper; `init` mismatch creates nothing, match creates an unlockable vault, refuses if a vault already exists; `set` refuses when no vault exists yet; scrubbing on both per-call and guard paths; crafted IPC client never gets raw values; `isatty=False` asserts `CREATE_NEW_CONSOLE`, bare argv, env handoff; password never in IPC; reveal/copy non-interactive returns status only; helper parent-death cancels; unlock→run→lock→fallback; reveal/copy ignore live guard; config/remove/`set` need password; audit with no plaintext; `--help` (including `init`); scrubber uses replace not regex.
