"""KeePassXC-Browser Native Messaging wire protocol.

Framing: uint32 little-endian length + UTF-8 JSON on stdin/stdout.
Session crypto: NaCl box (PyNaCl) with the extension — not vault AEAD.
"""

from __future__ import annotations

import base64
import json
import struct
from typing import Any, BinaryIO, Callable, Mapping

from nacl.public import Box, PrivateKey, PublicKey

from key_amnesia import __version__

# Native Messaging payload cap (KeePassXC NATIVEMSG_MAX_LENGTH).
NATIVEMSG_MAX_LENGTH = 1024 * 1024

# Association id returned to the extension (matches vault schema example).
ASSOCIATION_ID = "key-amnesia"

# Protocol version string shown to the extension (feature gating is loose).
PROTOCOL_VERSION = __version__

TRUE_STR = "true"

# KeePassXC error codes (BrowserMessageBuilder.h).
ERROR_DATABASE_NOT_OPENED = 1
ERROR_DATABASE_HASH_NOT_RECEIVED = 2
ERROR_CLIENT_PUBLIC_KEY_NOT_RECEIVED = 3
ERROR_CANNOT_DECRYPT_MESSAGE = 4
ERROR_TIMEOUT_OR_NOT_CONNECTED = 5
ERROR_ACTION_CANCELLED_OR_DENIED = 6
ERROR_CANNOT_ENCRYPT_MESSAGE = 7
ERROR_ASSOCIATION_FAILED = 8
ERROR_ENCRYPTION_KEY_UNRECOGNIZED = 10
ERROR_INCORRECT_ACTION = 12
ERROR_EMPTY_MESSAGE_RECEIVED = 13
ERROR_NO_URL_PROVIDED = 14
ERROR_NO_LOGINS_FOUND = 15

ERROR_MESSAGES: dict[int, str] = {
    ERROR_DATABASE_NOT_OPENED: "Database not opened",
    ERROR_DATABASE_HASH_NOT_RECEIVED: "Database hash not available",
    ERROR_CLIENT_PUBLIC_KEY_NOT_RECEIVED: "Client public key not received",
    ERROR_CANNOT_DECRYPT_MESSAGE: "Cannot decrypt message",
    ERROR_TIMEOUT_OR_NOT_CONNECTED: "Timeout or not connected to KeePassXC",
    ERROR_ACTION_CANCELLED_OR_DENIED: "Action cancelled or denied",
    ERROR_CANNOT_ENCRYPT_MESSAGE: "Message encryption failed.",
    ERROR_ASSOCIATION_FAILED: "KeePassXC association failed, try again",
    ERROR_ENCRYPTION_KEY_UNRECOGNIZED: "Encryption key is not recognized",
    ERROR_INCORRECT_ACTION: "Incorrect action",
    ERROR_EMPTY_MESSAGE_RECEIVED: "Empty message received",
    ERROR_NO_URL_PROVIDED: "No URL provided",
    ERROR_NO_LOGINS_FOUND: "No logins found",
}

SUPPORTED_ACTIONS = frozenset(
    {
        "change-public-keys",
        "get-databasehash",
        "associate",
        "test-associate",
        "get-logins",
    }
)

STUBBED_ACTIONS = frozenset(
    {
        "set-login",
        "generate-password",
        "create-new-group",
        "get-database-groups",
        "get-totp",
        "lock-database",
        "request-autotype",
        "passkeys-get",
        "passkeys-register",
        "delete-entry",
        "get-database-entries",
        "get-logins-count",
    }
)

FillRequestFn = Callable[..., dict[str, Any] | None]


def b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64decode(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def increment_nonce(nonce: bytes) -> bytes:
    """sodium_increment — little-endian byte-wise increment."""
    n = bytearray(nonce)
    for i in range(len(n)):
        n[i] = (n[i] + 1) & 0xFF
        if n[i] != 0:
            break
    return bytes(n)


def increment_nonce_b64(nonce_b64: str) -> str:
    return b64encode(increment_nonce(b64decode(nonce_b64)))


def error_reply(
    action: str,
    error_code: int,
    *,
    error: str | None = None,
    request_id: str | None = None,
) -> dict[str, Any]:
    reply: dict[str, Any] = {
        "action": action,
        "errorCode": str(error_code),
        "error": error
        if error is not None
        else ERROR_MESSAGES.get(error_code, "Unknown error"),
    }
    if request_id:
        reply["requestID"] = request_id
    return reply


def read_native_message(stream: BinaryIO) -> dict[str, Any] | None:
    """Read one Native Messaging frame. Returns None on clean EOF."""
    header = stream.read(4)
    if not header:
        return None
    if len(header) < 4:
        raise ValueError("truncated Native Messaging length header")
    (length,) = struct.unpack("<I", header)
    if length == 0:
        raise ValueError("empty Native Messaging payload")
    if length > NATIVEMSG_MAX_LENGTH:
        raise ValueError("Native Messaging payload too large")
    raw = stream.read(length)
    if len(raw) < length:
        raise ValueError("truncated Native Messaging payload")
    msg = json.loads(raw.decode("utf-8"))
    if not isinstance(msg, dict):
        raise TypeError("Native Messaging JSON must be an object")
    return msg


def write_native_message(stream: BinaryIO, message: Mapping[str, Any]) -> None:
    """Write one Native Messaging frame."""
    raw = json.dumps(message, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )
    if len(raw) > NATIVEMSG_MAX_LENGTH:
        raise ValueError("Native Messaging response too large")
    stream.write(struct.pack("<I", len(raw)))
    stream.write(raw)
    stream.flush()


class KeePassProtocol:
    """Stateful KeePassXC-Browser session for one native-host connection."""

    def __init__(
        self,
        *,
        fill_request: FillRequestFn | None = None,
        version: str = PROTOCOL_VERSION,
        association_id: str = ASSOCIATION_ID,
        fill_timeout: float = 120.0,
    ) -> None:
        self._fill_request = fill_request
        self.version = version
        self.association_id = association_id
        self.fill_timeout = fill_timeout
        self.client_public_key: PublicKey | None = None
        self.host_private_key: PrivateKey | None = None
        self.associated = False

    def _fill(self, msg: dict[str, Any]) -> dict[str, Any] | None:
        fn = self._fill_request
        if fn is None:
            from key_amnesia.browser_fill import browser_fill_request

            fn = browser_fill_request
            self._fill_request = fn
        return fn(msg, timeout=self.fill_timeout)

    def _box(self) -> Box | None:
        if self.client_public_key is None or self.host_private_key is None:
            return None
        return Box(self.host_private_key, self.client_public_key)

    def _encrypt(self, plaintext: Mapping[str, Any], nonce_b64: str) -> str | None:
        box = self._box()
        if box is None:
            return None
        try:
            nonce = b64decode(nonce_b64)
            raw = json.dumps(
                plaintext, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8")
            encrypted = box.encrypt(raw, nonce)
            return b64encode(encrypted.ciphertext)
        except Exception:
            return None

    def _decrypt(self, message_b64: str, nonce_b64: str) -> dict[str, Any] | None:
        box = self._box()
        if box is None:
            return None
        try:
            nonce = b64decode(nonce_b64)
            ciphertext = b64decode(message_b64)
            plain = box.decrypt(ciphertext, nonce)
            data = json.loads(plain.decode("utf-8"))
            if not isinstance(data, dict):
                return None
            return data
        except Exception:
            return None

    def _encrypted_response(
        self,
        action: str,
        request_nonce_b64: str,
        params: Mapping[str, Any],
    ) -> dict[str, Any]:
        resp_nonce = increment_nonce_b64(request_nonce_b64)
        inner: dict[str, Any] = {
            "version": self.version,
            "success": TRUE_STR,
            "nonce": resp_nonce,
        }
        inner.update(params)
        encrypted = self._encrypt(inner, resp_nonce)
        if encrypted is None:
            return error_reply(action, ERROR_CANNOT_ENCRYPT_MESSAGE)
        return {
            "action": action,
            "message": encrypted,
            "nonce": resp_nonce,
        }

    def _require_keys(self, action: str) -> dict[str, Any] | None:
        if self.client_public_key is None or self.host_private_key is None:
            return error_reply(action, ERROR_CLIENT_PUBLIC_KEY_NOT_RECEIVED)
        return None

    def _require_fill_session(
        self, action: str
    ) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        """Return (error_reply, status) — error if unlock/fill session absent."""
        status = self._fill({"verb": "status"})
        if status is None or not status.get("ok"):
            return error_reply(action, ERROR_DATABASE_NOT_OPENED), None
        if status.get("expired"):
            return error_reply(action, ERROR_DATABASE_NOT_OPENED), None
        return None, status

    def process(self, request: Mapping[str, Any] | None) -> dict[str, Any]:
        if not request:
            return error_reply("", ERROR_EMPTY_MESSAGE_RECEIVED)

        action = str(request.get("action") or "")
        if not action:
            return error_reply("", ERROR_INCORRECT_ACTION)

        if action == "change-public-keys":
            return self._handle_change_public_keys(request)

        if action in STUBBED_ACTIONS:
            return self._handle_stubbed(action, request)

        if action not in SUPPORTED_ACTIONS:
            return error_reply(action, ERROR_INCORRECT_ACTION)

        # Remaining actions need a live fill session (ka unlock). Never spawn
        # a master-password console from the native host.
        err, status = self._require_fill_session(action)
        if err is not None:
            return err

        if action == "get-databasehash":
            return self._handle_get_databasehash(request, status or {})
        if action == "associate":
            return self._handle_associate(request, status or {})
        if action == "test-associate":
            return self._handle_test_associate(request, status or {})
        if action == "get-logins":
            return self._handle_get_logins(request, status or {})

        return error_reply(action, ERROR_INCORRECT_ACTION)

    def _handle_stubbed(
        self, action: str, request: Mapping[str, Any]
    ) -> dict[str, Any]:
        request_id = request.get("requestID")
        if action == "set-login":
            msg = (
                "set-login is not supported; use `ka login add` "
                "(fresh auth) to create logins"
            )
        else:
            msg = f"{action} is not supported by key-amnesia v2"
        return error_reply(
            action,
            ERROR_INCORRECT_ACTION,
            error=msg,
            request_id=str(request_id) if request_id else None,
        )

    def _handle_change_public_keys(self, request: Mapping[str, Any]) -> dict[str, Any]:
        action = "change-public-keys"
        client_pk_b64 = str(request.get("publicKey") or "")
        nonce_b64 = str(request.get("nonce") or "")
        if not client_pk_b64 or not nonce_b64:
            return error_reply(action, ERROR_CLIENT_PUBLIC_KEY_NOT_RECEIVED)
        try:
            client_pk = PublicKey(b64decode(client_pk_b64))
        except Exception:
            return error_reply(action, ERROR_CLIENT_PUBLIC_KEY_NOT_RECEIVED)

        host_sk = PrivateKey.generate()
        self.client_public_key = client_pk
        self.host_private_key = host_sk
        self.associated = False

        resp_nonce = increment_nonce_b64(nonce_b64)
        return {
            "action": action,
            "version": self.version,
            "publicKey": b64encode(bytes(host_sk.public_key)),
            "success": TRUE_STR,
            "nonce": resp_nonce,
        }

    def _decode_request(
        self, request: Mapping[str, Any], action: str
    ) -> tuple[dict[str, Any] | None, str | None, dict[str, Any] | None]:
        key_err = self._require_keys(action)
        if key_err is not None:
            return key_err, None, None
        message_b64 = str(request.get("message") or "")
        nonce_b64 = str(request.get("nonce") or "")
        if not message_b64 or not nonce_b64:
            return error_reply(action, ERROR_CANNOT_DECRYPT_MESSAGE), None, None
        decrypted = self._decrypt(message_b64, nonce_b64)
        if decrypted is None:
            return error_reply(action, ERROR_CANNOT_DECRYPT_MESSAGE), None, None
        return None, increment_nonce_b64(nonce_b64), decrypted

    def _handle_get_databasehash(
        self, request: Mapping[str, Any], status: Mapping[str, Any]
    ) -> dict[str, Any]:
        action = "get-databasehash"
        err, _resp_nonce, decrypted = self._decode_request(request, action)
        if err is not None:
            return err
        assert decrypted is not None
        db_hash = str(status.get("database_id") or "")
        if not db_hash:
            return error_reply(action, ERROR_DATABASE_HASH_NOT_RECEIVED)
        return self._encrypted_response(
            action,
            str(request.get("nonce") or ""),
            {"action": "hash", "hash": db_hash},
        )

    def _handle_associate(
        self, request: Mapping[str, Any], status: Mapping[str, Any]
    ) -> dict[str, Any]:
        action = "associate"
        err, _resp_nonce, decrypted = self._decode_request(request, action)
        if err is not None:
            return err
        assert decrypted is not None

        key_b64 = str(decrypted.get("key") or "")
        id_key_b64 = str(decrypted.get("idKey") or "") or key_b64
        if not key_b64:
            return error_reply(action, ERROR_ASSOCIATION_FAILED)

        if self.client_public_key is None:
            return error_reply(action, ERROR_CLIENT_PUBLIC_KEY_NOT_RECEIVED)
        try:
            if b64decode(key_b64) != bytes(self.client_public_key):
                return error_reply(action, ERROR_ASSOCIATION_FAILED)
        except Exception:
            return error_reply(action, ERROR_ASSOCIATION_FAILED)

        store = self._fill(
            {
                "verb": "associate-store",
                "id": self.association_id,
                "id_key_b64": id_key_b64,
            }
        )
        if store is None or not store.get("ok"):
            return error_reply(action, ERROR_ACTION_CANCELLED_OR_DENIED)

        self.associated = True
        db_hash = str(status.get("database_id") or "")
        return self._encrypted_response(
            action,
            str(request.get("nonce") or ""),
            {"hash": db_hash, "id": self.association_id},
        )

    def _handle_test_associate(
        self, request: Mapping[str, Any], status: Mapping[str, Any]
    ) -> dict[str, Any]:
        action = "test-associate"
        err, _resp_nonce, decrypted = self._decode_request(request, action)
        if err is not None:
            return err
        assert decrypted is not None

        assoc_id = str(decrypted.get("id") or "")
        key_b64 = str(decrypted.get("key") or "")
        if not assoc_id or not key_b64:
            return error_reply(action, ERROR_DATABASE_NOT_OPENED)

        result = self._fill({"verb": "test-associate", "id": assoc_id})
        if result is None or not result.get("ok") or not result.get("associated"):
            return error_reply(action, ERROR_ASSOCIATION_FAILED)

        self.associated = True
        db_hash = str(status.get("database_id") or "")
        return self._encrypted_response(
            action,
            str(request.get("nonce") or ""),
            {"hash": db_hash, "id": assoc_id},
        )

    def _handle_get_logins(
        self, request: Mapping[str, Any], status: Mapping[str, Any]
    ) -> dict[str, Any]:
        action = "get-logins"
        if not self.associated:
            return error_reply(action, ERROR_ASSOCIATION_FAILED)

        err, _resp_nonce, decrypted = self._decode_request(request, action)
        if err is not None:
            return err
        assert decrypted is not None

        url = str(decrypted.get("url") or "")
        if not url:
            return error_reply(action, ERROR_NO_URL_PROVIDED)

        submit_url = decrypted.get("submitUrl")
        fill_msg: dict[str, Any] = {
            "verb": "get-logins-for-url",
            "url": url,
        }
        if submit_url:
            fill_msg["submit_url"] = str(submit_url)

        # Hold the Native Messaging request open for approval + fill IPC RTT.
        result = self._fill(fill_msg)
        if result is None:
            return error_reply(action, ERROR_DATABASE_NOT_OPENED)
        if not result.get("ok"):
            reason = str(result.get("reason") or "")
            lowered = reason.lower()
            if reason in ("denied", "timeout") or "denied" in lowered or "timeout" in lowered:
                return error_reply(action, ERROR_ACTION_CANCELLED_OR_DENIED)
            return error_reply(action, ERROR_NO_LOGINS_FOUND)

        entries = result.get("entries") or []
        if not isinstance(entries, list) or not entries:
            return error_reply(action, ERROR_NO_LOGINS_FOUND)

        out_entries: list[dict[str, Any]] = []
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            item: dict[str, Any] = {
                "login": str(entry.get("login") or ""),
                "name": str(entry.get("name") or ""),
                "password": str(entry.get("password") or ""),
            }
            if entry.get("uuid") is not None:
                item["uuid"] = str(entry.get("uuid"))
            out_entries.append(item)

        if not out_entries:
            return error_reply(action, ERROR_NO_LOGINS_FOUND)

        db_hash = str(status.get("database_id") or "")
        assoc_id = str(decrypted.get("id") or self.association_id)
        return self._encrypted_response(
            action,
            str(request.get("nonce") or ""),
            {
                "count": str(len(out_entries)),
                "entries": out_entries,
                "hash": db_hash,
                "id": assoc_id,
            },
        )
