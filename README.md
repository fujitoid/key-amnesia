# key-amnesia

Encrypted secret vault for agent-driven CLIs. Secrets stay behind a human prompt; commands get env injection and **buffer-then-scrub** output redaction. Windows-primary.

```bash
pip install -e .
key-amnesia --help   # or: ka --help
```

## Why

Agents need API keys and passwords to run tools, but should not hold long-lived plaintext. key-amnesia stores values in an Argon2id + SecretBox vault, prompts a human (inline TTY or a new Windows console), injects secrets only into a child process, then redacts exact echoes from stdout/stderr before the agent sees them.

## Quick start

```bash
# Store a secret (prompts for master password; prefer omitting value on argv)
ka set openai_key

# List names only (no prompt — reads plaintext names sidecar)
ka list

# Run a command with the secret in the environment; output is scrubbed after exit
ka run --secret openai_key --as openai_key=OPENAI_API_KEY -- curl -s https://api.example.com

# Always-fresh auth (never uses a live guard shortcut)
ka reveal openai_key
ka copy openai_key

# Cached session (optional)
ka config set session-mode cached
ka unlock
ka run --secret openai_key --as openai_key=OPENAI_API_KEY -- some-cmd
ka lock
```

Data directory: `~/.key-amnesia/` (override with `KEY_AMNESIA_HOME`). Vault path override: `KEY_AMNESIA_VAULT_PATH`.

## Console routing

```
Needs human auth
  ├─ stdin is a TTY  → getpass inline → decrypt in-process
  └─ not a TTY       → spawn helper with CREATE_NEW_CONSOLE
                        (bare argv: `_prompt-helper` only;
                         request / authkey / reply address via env)
                        → parent waits on IPC (default 90s)
                        → status / scrubbed I/O only — never password, never raw secrets
```

**POSIX non-interactive spawn is out of scope for v0** — fail closed with a clear error. Use an interactive terminal, or Windows.

Nothing sensitive is placed on argv (Windows event 4688 records command lines).

## Session modes

| Mode | Behavior |
|------|----------|
| `per-call` (default) | Each privileged op prompts; plaintext discarded after use |
| `cached` | `unlock` starts a guard process holding the decrypted vault until timeout / `lock` |

**Always fresh master-password auth** (never a guard shortcut): `set`, `remove`, `config set`, `reveal`, `copy`.

Live guard may satisfy `run` / `list` without a prompt. Guard IPC verbs: `run`, `list`, `lock`, `status`, `renew` only — **no** `get-value` / `reveal`.

### Who decrypts

| Path | Decryptor | What the agent-facing process gets |
|------|-----------|--------------------------------------|
| Interactive `run` | CLI | Scrubbed stdout/stderr + exit |
| Non-interactive `run` | Helper (decrypts **and** executes) | Scrubbed stdout/stderr + exit |
| Cached `run` | Guard | Scrubbed stdout/stderr + exit |
| Non-interactive `reveal` / `copy` | Helper window only | Status flag (`shown` / `copied`) |

## Commands

| Command | Notes |
|---------|--------|
| `set NAME [VALUE]` | Fresh auth; updates vault + names sidecar |
| `remove NAME` | Fresh auth |
| `run --secret/--as ... -- cmd` | Guard hit or per-call; buffer-then-scrub |
| `list` | Names sidecar / guard; never values |
| `unlock` / `lock` | Cached session control |
| `reveal` / `copy` | Fresh auth; display/copy location follows TTY vs helper |
| `config show` / `config set KEY VALUE` | `set` requires fresh auth |
| `status` | Guard session info |

Internal: `_prompt-helper`, `_guard` (bare argv; omitted from top-level help summary; still support `--help`).

## Cryptography & files

- **KDF:** Argon2id `OPSLIMIT_SENSITIVE` / `MEMLIMIT_SENSITIVE` only (never dialed down).
- **Vault:** `vault.bin` — `KAM1` header + SecretBox blob.
- **Names sidecar:** `vault.names.json` — `{"names":[...]}` for prompt-free `list`.
- **Config:** `session-mode`, `session-timeout-minutes`, `prompt-timeout-seconds`.
- **Guard lock:** pipe address + `authkey_hex` + pid + expiry. **No `session_key`.**
- **Audit:** `audit.log` JSONL — actions, names, routes, results; never secret values.

## Threat model (honest)

Read this before relying on key-amnesia in a hostile environment.

1. **Residual scrubbing risk.** The target command can print the secret. Scrubbing mitigates **exact substring echoes only**. Base64, hex, chunked, or otherwise obfuscated echoes still slip through.
2. **Output is not live.** Child stdout/stderr are fully buffered, scrubbed, then relayed. The agent sees output only after the command exits.
3. **Secret names are plaintext on disk** via `vault.names.json`. Values are encrypted. DPAPI (or similar) protection of the sidecar is **out of scope for v0**.
4. **Human console assumption.** We assume the invoking agent cannot GUI-automate or synthesize keystrokes against the spawned authentication console.
5. **Headless / no interactive session.** Fail closed — there is no non-interactive way to supply the master password without a spawned console.
6. **Same-user process isolation (ssh-agent parallel).** Any process running as the same user can talk to a live guard (authkey is in `guard.lock`). The guard **never returns raw secret values** — damage is bounded to `run` / `list` / session control — but this does **not** close the same-user gap.
7. **Master password never on IPC** and is never satisfiable non-interactively without a spawned console.

## Development

```bash
pip install -e ".[dev]"
pytest
```

See [DESIGN.md](DESIGN.md) for formats, invariants, and module layout.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
