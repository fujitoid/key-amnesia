"""Unit tests for KeePassXC-Browser wire protocol helpers."""

from __future__ import annotations

import io
import json
import struct
from typing import Any

import pytest
from nacl.public import Box, PrivateKey, PublicKey

from key_amnesia.keepass_protocol import (
    ASSOCIATION_ID,
    ERROR_ACTION_CANCELLED_OR_DENIED,
    ERROR_ASSOCIATION_FAILED,
    ERROR_DATABASE_NOT_OPENED,
    ERROR_INCORRECT_ACTION,
    ERROR_NO_LOGINS_FOUND,
    KeePassProtocol,
    b64decode,
    b64encode,
    increment_nonce,
    increment_nonce_b64,
    read_native_message,
    write_native_message,
)


def _nonce() -> bytes:
    return b"\x01" * 24


def _client_keys() -> tuple[PrivateKey, str]:
    sk = PrivateKey.generate()
    return sk, b64encode(bytes(sk.public_key))


class FakeFill:
    """In-memory fill IPC stand-in for protocol unit tests."""

    def __init__(
        self,
        *,
        available: bool = True,
        database_id: str = "dbhashabc",
        associations: list[dict[str, str]] | None = None,
        entries: list[dict[str, str]] | None = None,
        approve: bool = True,
        deny_reason: str = "denied",
    ) -> None:
        self.available = available
        self.database_id = database_id
        self.associations = list(associations or [])
        self.entries = list(entries or [])
        self.approve = approve
        self.deny_reason = deny_reason
        self.calls: list[dict[str, Any]] = []

    def __call__(
        self, msg: dict[str, Any], timeout: float = 120.0
    ) -> dict[str, Any] | None:
        self.calls.append(dict(msg))
        if not self.available:
            return None
        verb = msg.get("verb")
        if verb == "status":
            return {
                "ok": True,
                "database_id": self.database_id,
                "login_count": len(self.entries),
                "associated": bool(self.associations),
                "expired": False,
            }
        if verb == "associate-store":
            aid = str(msg.get("id") or "")
            key = str(msg.get("id_key_b64") or "")
            self.associations = [e for e in self.associations if e.get("id") != aid]
            self.associations.append({"id": aid, "id_key_b64": key})
            return {"ok": True, "associated": True, "id": aid}
        if verb == "test-associate":
            aid = str(msg.get("id") or "")
            for e in self.associations:
                if e.get("id") == aid:
                    return {"ok": True, "associated": True, "id": aid}
            return {"ok": False, "associated": False, "reason": "not associated"}
        if verb == "get-logins-for-url":
            if not self.approve:
                return {"ok": False, "reason": self.deny_reason}
            if not self.entries:
                return {"ok": False, "reason": "no matching logins"}
            return {"ok": True, "entries": list(self.entries)}
        return {"ok": False, "reason": f"unknown verb: {verb}"}


def _handshake(proto: KeePassProtocol, client_sk: PrivateKey) -> str:
    nonce = b64encode(_nonce())
    resp = proto.process(
        {
            "action": "change-public-keys",
            "publicKey": b64encode(bytes(client_sk.public_key)),
            "nonce": nonce,
            "clientID": "test-client",
        }
    )
    assert resp.get("success") == "true"
    assert "publicKey" in resp
    return str(resp["publicKey"])


def _encrypt_to_host(
    client_sk: PrivateKey,
    host_pk_b64: str,
    nonce_b64: str,
    payload: dict[str, Any],
) -> str:
    box = Box(client_sk, PublicKey(b64decode(host_pk_b64)))
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return b64encode(box.encrypt(raw, b64decode(nonce_b64)).ciphertext)


def _decrypt_from_host(
    client_sk: PrivateKey,
    host_pk_b64: str,
    nonce_b64: str,
    message_b64: str,
) -> dict[str, Any]:
    box = Box(client_sk, PublicKey(b64decode(host_pk_b64)))
    plain = box.decrypt(b64decode(message_b64), b64decode(nonce_b64))
    data = json.loads(plain.decode("utf-8"))
    assert isinstance(data, dict)
    return data


def _encrypted_action(
    proto: KeePassProtocol,
    client_sk: PrivateKey,
    host_pk_b64: str,
    action: str,
    inner: dict[str, Any],
    nonce: bytes | None = None,
) -> dict[str, Any]:
    n = nonce or _nonce()
    nonce_b64 = b64encode(n)
    inner = {**inner, "action": action}
    msg = _encrypt_to_host(client_sk, host_pk_b64, nonce_b64, inner)
    return proto.process(
        {
            "action": action,
            "message": msg,
            "nonce": nonce_b64,
            "clientID": "test-client",
        }
    )


def test_increment_nonce_little_endian() -> None:
    n = bytes([255, 0, 0]) + bytes(21)
    assert increment_nonce(n)[0] == 0
    assert increment_nonce(n)[1] == 1
    assert increment_nonce_b64(b64encode(bytes(24))) == b64encode(
        b"\x01" + bytes(23)
    )


def test_native_message_framing_roundtrip() -> None:
    buf = io.BytesIO()
    payload = {"action": "change-public-keys", "nonce": "abc"}
    write_native_message(buf, payload)
    raw = buf.getvalue()
    (length,) = struct.unpack("<I", raw[:4])
    assert length == len(raw) - 4
    buf.seek(0)
    assert read_native_message(buf) == payload
    assert read_native_message(buf) is None


def test_change_public_keys_and_get_databasehash() -> None:
    fill = FakeFill(database_id="hash123")
    proto = KeePassProtocol(fill_request=fill)
    client_sk, _ = _client_keys()
    host_pk = _handshake(proto, client_sk)

    resp = _encrypted_action(
        proto,
        client_sk,
        host_pk,
        "get-databasehash",
        {"action": "get-databasehash"},
    )
    assert "message" in resp
    inner = _decrypt_from_host(
        client_sk, host_pk, str(resp["nonce"]), str(resp["message"])
    )
    assert inner["success"] == "true"
    assert inner["hash"] == "hash123"
    assert inner["action"] == "hash"


def test_no_session_returns_database_not_opened() -> None:
    fill = FakeFill(available=False)
    proto = KeePassProtocol(fill_request=fill)
    client_sk, _ = _client_keys()
    host_pk = _handshake(proto, client_sk)

    resp = _encrypted_action(
        proto,
        client_sk,
        host_pk,
        "get-databasehash",
        {"action": "get-databasehash"},
    )
    assert resp.get("errorCode") == str(ERROR_DATABASE_NOT_OPENED)
    assert "Database not opened" in str(resp.get("error"))


def test_associate_and_test_associate() -> None:
    fill = FakeFill()
    proto = KeePassProtocol(fill_request=fill)
    client_sk, client_pk_b64 = _client_keys()
    host_pk = _handshake(proto, client_sk)

    id_key = PrivateKey.generate()
    id_key_b64 = b64encode(bytes(id_key.public_key))
    resp = _encrypted_action(
        proto,
        client_sk,
        host_pk,
        "associate",
        {
            "action": "associate",
            "key": client_pk_b64,
            "idKey": id_key_b64,
        },
        nonce=_nonce(),
    )
    assert "message" in resp
    inner = _decrypt_from_host(
        client_sk, host_pk, str(resp["nonce"]), str(resp["message"])
    )
    assert inner["id"] == ASSOCIATION_ID
    assert proto.associated is True
    assert fill.associations[0]["id_key_b64"] == id_key_b64

    proto2 = KeePassProtocol(fill_request=fill)
    host_pk2 = _handshake(proto2, client_sk)
    resp2 = _encrypted_action(
        proto2,
        client_sk,
        host_pk2,
        "test-associate",
        {"action": "test-associate", "id": ASSOCIATION_ID, "key": id_key_b64},
        nonce=increment_nonce(_nonce()),
    )
    assert "message" in resp2
    inner2 = _decrypt_from_host(
        client_sk, host_pk2, str(resp2["nonce"]), str(resp2["message"])
    )
    assert inner2["success"] == "true"
    assert inner2["id"] == ASSOCIATION_ID


def test_associate_rejects_mismatched_session_key() -> None:
    fill = FakeFill()
    proto = KeePassProtocol(fill_request=fill)
    client_sk, _ = _client_keys()
    host_pk = _handshake(proto, client_sk)
    other_pk = b64encode(bytes(PrivateKey.generate().public_key))
    resp = _encrypted_action(
        proto,
        client_sk,
        host_pk,
        "associate",
        {"action": "associate", "key": other_pk, "idKey": other_pk},
    )
    assert resp.get("errorCode") == str(ERROR_ASSOCIATION_FAILED)


def test_get_logins_returns_entries() -> None:
    fill = FakeFill(
        entries=[
            {
                "login": "alice",
                "name": "api_key",
                "password": "super-secret-value-123",
                "uuid": "api_key",
            }
        ]
    )
    proto = KeePassProtocol(fill_request=fill)
    client_sk, client_pk_b64 = _client_keys()
    host_pk = _handshake(proto, client_sk)
    _encrypted_action(
        proto,
        client_sk,
        host_pk,
        "associate",
        {
            "action": "associate",
            "key": client_pk_b64,
            "idKey": client_pk_b64,
        },
    )

    resp = _encrypted_action(
        proto,
        client_sk,
        host_pk,
        "get-logins",
        {
            "action": "get-logins",
            "url": "https://example.com/login",
            "keys": [{"id": ASSOCIATION_ID, "key": client_pk_b64}],
        },
        nonce=increment_nonce(increment_nonce(_nonce())),
    )
    assert "message" in resp
    inner = _decrypt_from_host(
        client_sk, host_pk, str(resp["nonce"]), str(resp["message"])
    )
    assert inner["count"] == "1"
    assert inner["entries"][0]["password"] == "super-secret-value-123"
    assert inner["entries"][0]["login"] == "alice"
    assert any(c.get("verb") == "get-logins-for-url" for c in fill.calls)


def test_get_logins_requires_association() -> None:
    fill = FakeFill(
        entries=[{"login": "a", "name": "n", "password": "p"}],
    )
    proto = KeePassProtocol(fill_request=fill)
    client_sk, _ = _client_keys()
    host_pk = _handshake(proto, client_sk)
    resp = _encrypted_action(
        proto,
        client_sk,
        host_pk,
        "get-logins",
        {"action": "get-logins", "url": "https://example.com"},
    )
    assert resp.get("errorCode") == str(ERROR_ASSOCIATION_FAILED)


def test_get_logins_denied_maps_to_cancelled() -> None:
    fill = FakeFill(
        entries=[{"login": "a", "name": "n", "password": "p"}],
        approve=False,
    )
    proto = KeePassProtocol(fill_request=fill)
    client_sk, client_pk_b64 = _client_keys()
    host_pk = _handshake(proto, client_sk)
    _encrypted_action(
        proto,
        client_sk,
        host_pk,
        "associate",
        {"action": "associate", "key": client_pk_b64, "idKey": client_pk_b64},
    )
    resp = _encrypted_action(
        proto,
        client_sk,
        host_pk,
        "get-logins",
        {"action": "get-logins", "url": "https://example.com"},
        nonce=increment_nonce(_nonce()),
    )
    assert resp.get("errorCode") == str(ERROR_ACTION_CANCELLED_OR_DENIED)


def test_get_logins_empty_maps_to_no_logins() -> None:
    fill = FakeFill(entries=[], approve=True)
    proto = KeePassProtocol(fill_request=fill)
    client_sk, client_pk_b64 = _client_keys()
    host_pk = _handshake(proto, client_sk)
    _encrypted_action(
        proto,
        client_sk,
        host_pk,
        "associate",
        {"action": "associate", "key": client_pk_b64, "idKey": client_pk_b64},
    )
    fill.entries = []
    resp = _encrypted_action(
        proto,
        client_sk,
        host_pk,
        "get-logins",
        {"action": "get-logins", "url": "https://example.com"},
        nonce=increment_nonce(_nonce()),
    )
    assert resp.get("errorCode") == str(ERROR_NO_LOGINS_FOUND)


@pytest.mark.parametrize(
    "action",
    [
        "set-login",
        "generate-password",
        "get-totp",
        "passkeys-get",
        "create-new-group",
    ],
)
def test_stubbed_actions_return_clear_error(action: str) -> None:
    proto = KeePassProtocol(fill_request=FakeFill())
    resp = proto.process({"action": action, "nonce": b64encode(_nonce())})
    assert resp.get("errorCode") == str(ERROR_INCORRECT_ACTION)
    assert "not supported" in str(resp.get("error")).lower()
    if action == "set-login":
        assert "ka login add" in str(resp.get("error"))


def test_set_login_stub_does_not_need_fill_session() -> None:
    """Stubbed actions must not require unlock (no password spawn path)."""
    fill = FakeFill(available=False)
    proto = KeePassProtocol(fill_request=fill)
    resp = proto.process({"action": "set-login", "nonce": b64encode(_nonce())})
    assert resp.get("errorCode") == str(ERROR_INCORRECT_ACTION)
    assert fill.calls == []
