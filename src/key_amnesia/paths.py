"""Path helpers for key-amnesia data directory and files."""

from __future__ import annotations

import os
import stat
from pathlib import Path


ENV_HOME = "KEY_AMNESIA_HOME"
ENV_VAULT_PATH = "KEY_AMNESIA_VAULT_PATH"


def data_dir() -> Path:
    """Return the key-amnesia data directory, creating it with restrictive perms."""
    override = os.environ.get(ENV_HOME)
    if override:
        root = Path(override)
    else:
        root = Path.home() / ".key-amnesia"
    root.mkdir(parents=True, exist_ok=True)
    try:
        root.chmod(0o700)
    except OSError:
        # Windows may not honor POSIX mode bits; user-profile ACL is the default.
        pass
    return root


def vault_path() -> Path:
    override = os.environ.get(ENV_VAULT_PATH)
    if override:
        return Path(override)
    return data_dir() / "vault.bin"


def names_path() -> Path:
    """Names sidecar lives next to the vault file."""
    vp = vault_path()
    return vp.with_name(vp.stem + ".names.json")


def config_path() -> Path:
    return data_dir() / "config.json"


def guard_lock_path() -> Path:
    return data_dir() / "guard.lock"


def admitted_session_token_path() -> Path:
    """Opaque admission token minted by a live guard for the current session."""
    return data_dir() / "admitted_session.token"


def last_guard_state_path() -> Path:
    """Honest-death-reporting record written by the guard on every teardown."""
    return data_dir() / "last_guard_state.json"


def audit_log_path() -> Path:
    return data_dir() / "audit.log"
