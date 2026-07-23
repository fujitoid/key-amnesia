"""Vault binary layout, load/save, and names sidecar."""

from __future__ import annotations

import json
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from key_amnesia import crypto
from key_amnesia import theme
from key_amnesia.paths import names_path, vault_path

MAGIC = b"KAM1"
VERSION = 1
HEADER_FMT = "<4sB16sQQ"  # magic, version, salt, opslimit, memlimit
HEADER_SIZE = struct.calcsize(HEADER_FMT)

# Obsolete browser-fill payload keys, removed in 0.3.0. Dropped on load/save
# so old vaults migrate forward automatically; see _normalize_payload.
_OBSOLETE_FILL_KEYS = ("logins", "browser_associations", "database_id")


class VaultError(Exception):
    """Vault I/O or format error."""


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def empty_payload() -> dict[str, Any]:
    now = _utc_now_iso()
    return {
        "secrets": {},
        "created_at": now,
        "updated_at": now,
    }


def _normalize_payload(payload: dict[str, Any], *, warn: bool = True) -> dict[str, Any]:
    """Drop obsolete browser-fill keys (removed in 0.3.0) before use.

    Prints a one-time informational notice only when there was a non-empty
    ``logins`` list to actually lose; empty/absent obsolete keys are dropped
    silently. Callers that immediately re-save the payload (e.g. ``load_vault``
    followed by a mutation + ``save_vault``) should only warn once — pass
    ``warn=False`` on the save-side normalization.
    """
    if any(key in payload for key in _OBSOLETE_FILL_KEYS):
        logins = payload.get("logins")
        if warn and isinstance(logins, list) and logins:
            theme.info(
                "Removed obsolete login associations - browser-fill was "
                "removed in 0.3.0."
            )
        for key in _OBSOLETE_FILL_KEYS:
            payload.pop(key, None)
    return payload


def load_vault(path: Path | str | None, password: str) -> dict[str, Any]:
    """Decrypt and return the vault JSON payload."""
    p = Path(path) if path is not None else vault_path()
    if not p.exists():
        raise VaultError(f"Vault not found: {p}")
    data = p.read_bytes()
    if len(data) < HEADER_SIZE:
        raise VaultError("Vault file too short")
    magic, version, salt, opslimit, memlimit = struct.unpack(
        HEADER_FMT, data[:HEADER_SIZE]
    )
    if magic != MAGIC:
        raise VaultError("Invalid vault magic")
    if version != VERSION:
        raise VaultError(f"Unsupported vault version: {version}")
    blob = data[HEADER_SIZE:]
    key = crypto.derive_key(
        password.encode("utf-8"),
        salt,
        opslimit=opslimit,
        memlimit=memlimit,
    )
    try:
        plaintext = crypto.decrypt(key, blob)
    except crypto.CryptoError_ as e:
        raise VaultError(str(e)) from e
    try:
        payload = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise VaultError("Vault payload is corrupt") from e
    if not isinstance(payload, dict) or "secrets" not in payload:
        raise VaultError("Vault payload missing secrets")
    return _normalize_payload(payload)


def save_vault(
    path: Path | str | None,
    password: str,
    payload: dict[str, Any],
    *,
    salt: bytes | None = None,
) -> None:
    """Encrypt and write the vault. Always uses OPSLIMIT/MEMLIMIT_SENSITIVE."""
    p = Path(path) if path is not None else vault_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    if salt is None:
        # Preserve salt if vault already exists (same password re-encrypt).
        if p.exists() and len(p.read_bytes()) >= HEADER_SIZE:
            existing = p.read_bytes()
            _, _, salt, _, _ = struct.unpack(HEADER_FMT, existing[:HEADER_SIZE])
        else:
            salt = crypto.generate_salt()
    opslimit = crypto.OPSLIMIT
    memlimit = crypto.MEMLIMIT
    key = crypto.derive_key(
        password.encode("utf-8"),
        salt,
        opslimit=opslimit,
        memlimit=memlimit,
    )
    # Silent here: load_vault already surfaced the migration notice (if any)
    # on the read side of a load-then-save round trip.
    body = _normalize_payload(dict(payload), warn=False)
    if "created_at" not in body:
        body["created_at"] = _utc_now_iso()
    body["updated_at"] = _utc_now_iso()
    if "secrets" not in body:
        body["secrets"] = {}
    plaintext = json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")
    blob = crypto.encrypt(key, plaintext)
    header = struct.pack(HEADER_FMT, MAGIC, VERSION, salt, opslimit, memlimit)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_bytes(header + blob)
    tmp.replace(p)
    # Keep names sidecar in sync with encrypted secrets keys.
    write_names(sorted(body["secrets"].keys()), names_path_for_vault(p))


def names_path_for_vault(vault: Path) -> Path:
    return vault.with_name(vault.stem + ".names.json")


def read_names(path: Path | None = None) -> list[str]:
    p = path or names_path()
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    names = data.get("names", []) if isinstance(data, dict) else []
    if not isinstance(names, list):
        return []
    return [str(n) for n in names]


def write_names(names: list[str], path: Path | None = None) -> None:
    p = path or names_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    payload = {"names": sorted(set(names))}
    p.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def update_names_after_mutation(secrets: dict[str, str], vault: Path | None = None) -> None:
    vp = vault or vault_path()
    write_names(sorted(secrets.keys()), names_path_for_vault(vp))
