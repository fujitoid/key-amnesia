"""Argon2id KDF + SecretBox helpers for vault encryption."""

from __future__ import annotations

import nacl.pwhash
import nacl.secret
import nacl.utils
from nacl.exceptions import CryptoError

# Locked to SENSITIVE only — never dial down.
OPSLIMIT = nacl.pwhash.argon2id.OPSLIMIT_SENSITIVE
MEMLIMIT = nacl.pwhash.argon2id.MEMLIMIT_SENSITIVE

KEY_SIZE = nacl.secret.SecretBox.KEY_SIZE
SALT_SIZE = nacl.pwhash.argon2id.SALTBYTES


class CryptoError_(Exception):
    """Raised when decryption or authentication fails."""


def generate_salt() -> bytes:
    return nacl.utils.random(SALT_SIZE)


def derive_key(
    password: bytes,
    salt: bytes,
    opslimit: int = OPSLIMIT,
    memlimit: int = MEMLIMIT,
) -> bytes:
    """Derive a SecretBox key via Argon2id.

    opslimit/memlimit default to SENSITIVE. Callers must not pass weaker values
    for new vaults; load_vault may read stored params for compatibility with the
    on-disk header, but save_vault always writes SENSITIVE.
    """
    return nacl.pwhash.argon2id.kdf(
        KEY_SIZE,
        password,
        salt,
        opslimit=opslimit,
        memlimit=memlimit,
    )


def encrypt(key: bytes, plaintext: bytes) -> bytes:
    box = nacl.secret.SecretBox(key)
    return box.encrypt(plaintext)


def decrypt(key: bytes, ciphertext: bytes) -> bytes:
    box = nacl.secret.SecretBox(key)
    try:
        return box.decrypt(ciphertext)
    except CryptoError as e:
        raise CryptoError_("Decryption failed (wrong password or tampered data)") from e
