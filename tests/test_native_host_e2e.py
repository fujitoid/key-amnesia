"""End-to-end Native Messaging host tests (fake extension over pipes)."""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any

from nacl.public import Box, PrivateKey, PublicKey

from key_amnesia.keepass_protocol import (
    ASSOCIATION_ID,
    ERROR_DATABASE_NOT_OPENED,
    ERROR_INCORRECT_ACTION,
    KeePassProtocol,
    b64decode,
    b64encode,
    read_native_message,
    write_native_message,
)
from key_amnesia.native_host import run_host
from key_amnesia.paths import audit_log_path


def _nonce_at(n: int) -> bytes:
    base = bytearray(24)
    for _ in range(n):
        for i in range(len(base)):
            base[i] = (base[i] + 1) & 0xFF
            if base[i] != 0:
                break
    return bytes(base)


class FakeFill:
    def __init__(self) -> None:
        self.database_id = "e2e-database-hash"
        self.associations: list[dict[str, str]] = []
        self.password = "protocol-only-password-xyz"
        self.calls: list[dict[str, Any]] = []

    def __call__(
        self, msg: dict[str, Any], timeout: float = 120.0
    ) -> dict[str, Any] | None:
        self.calls.append(dict(msg))
        verb = msg.get("verb")
        if verb == "status":
            return {
                "ok": True,
                "database_id": self.database_id,
                "login_count": 1,
                "associated": bool(self.associations),
                "expired": False,
            }
        if verb == "associate-store":
            self.associations.append(
                {
                    "id": str(msg.get("id") or ""),
                    "id_key_b64": str(msg.get("id_key_b64") or ""),
                }
            )
            return {"ok": True, "associated": True, "id": msg.get("id")}
        if verb == "test-associate":
            aid = str(msg.get("id") or "")
            for e in self.associations:
                if e.get("id") == aid:
                    return {"ok": True, "associated": True, "id": aid}
            return {"ok": False, "associated": False}
        if verb == "get-logins-for-url":
            return {
                "ok": True,
                "entries": [
                    {
                        "login": "alice",
                        "name": "api_key",
                        "password": self.password,
                        "uuid": "api_key",
                    }
                ],
            }
        return {"ok": False, "reason": "unknown"}


def _encrypt(
    client_sk: PrivateKey, host_pk_b64: str, nonce: bytes, payload: dict[str, Any]
) -> str:
    box = Box(client_sk, PublicKey(b64decode(host_pk_b64)))
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return b64encode(box.encrypt(raw, nonce).ciphertext)


def _decrypt(
    client_sk: PrivateKey, host_pk_b64: str, nonce_b64: str, message_b64: str
) -> dict[str, Any]:
    box = Box(client_sk, PublicKey(b64decode(host_pk_b64)))
    plain = box.decrypt(b64decode(message_b64), b64decode(nonce_b64))
    data = json.loads(plain.decode("utf-8"))
    assert isinstance(data, dict)
    return data


def _run_scripted_session(
    requests: list[dict[str, Any]],
    *,
    protocol: KeePassProtocol,
) -> list[dict[str, Any]]:
    """Feed NM requests through run_host; collect framed responses."""
    stdin = io.BytesIO()
    for req in requests:
        write_native_message(stdin, req)
    stdin.seek(0)
    stdout = io.BytesIO()
    rc = run_host(
        stdin=stdin,
        stdout=stdout,
        protocol=protocol,
        stderr=io.StringIO(),
    )
    assert rc == 0
    stdout.seek(0)
    responses: list[dict[str, Any]] = []
    while True:
        msg = read_native_message(stdout)
        if msg is None:
            break
        responses.append(msg)
    return responses


def test_e2e_handshake_associate_get_logins(ka_home: Path) -> None:
    """Password appears in encrypted protocol response; never in audit.log."""
    fill = FakeFill()
    client_sk = PrivateKey.generate()
    client_pk = b64encode(bytes(client_sk.public_key))
    proto = KeePassProtocol(fill_request=fill)

    n0 = _nonce_at(0)
    hs = proto.process(
        {
            "action": "change-public-keys",
            "publicKey": client_pk,
            "nonce": b64encode(n0),
            "clientID": "e2e",
        }
    )
    assert hs.get("success") == "true"
    host_pk = str(hs["publicKey"])

    # Distinct nonces for each encrypted request (avoid NaCl nonce reuse).
    n1 = _nonce_at(10)
    n2 = _nonce_at(20)
    requests = [
        {
            "action": "associate",
            "message": _encrypt(
                client_sk,
                host_pk,
                n1,
                {"action": "associate", "key": client_pk, "idKey": client_pk},
            ),
            "nonce": b64encode(n1),
            "clientID": "e2e",
        },
        {
            "action": "get-logins",
            "message": _encrypt(
                client_sk,
                host_pk,
                n2,
                {
                    "action": "get-logins",
                    "url": "https://example.com",
                    "keys": [{"id": ASSOCIATION_ID, "key": client_pk}],
                },
            ),
            "nonce": b64encode(n2),
            "clientID": "e2e",
        },
    ]
    responses = _run_scripted_session(requests, protocol=proto)
    assert len(responses) == 2
    assert responses[0]["action"] == "associate"
    assert responses[1]["action"] == "get-logins"

    assoc_inner = _decrypt(
        client_sk, host_pk, str(responses[0]["nonce"]), str(responses[0]["message"])
    )
    assert assoc_inner["id"] == ASSOCIATION_ID

    logins_inner = _decrypt(
        client_sk, host_pk, str(responses[1]["nonce"]), str(responses[1]["message"])
    )
    assert logins_inner["entries"][0]["password"] == fill.password
    assert logins_inner["entries"][0]["login"] == "alice"

    audit = audit_log_path()
    if audit.exists():
        assert fill.password not in audit.read_text(encoding="utf-8")
    # Outer NM JSON keeps the password inside the NaCl box only.
    assert fill.password not in json.dumps(responses[1])


def test_e2e_no_session_database_locked(ka_home: Path) -> None:
    client_sk = PrivateKey.generate()
    client_pk = b64encode(bytes(client_sk.public_key))
    proto = KeePassProtocol(fill_request=lambda msg, timeout=120.0: None)

    n0 = _nonce_at(0)
    hs = proto.process(
        {
            "action": "change-public-keys",
            "publicKey": client_pk,
            "nonce": b64encode(n0),
            "clientID": "e2e",
        }
    )
    host_pk = str(hs["publicKey"])
    n1 = _nonce_at(10)
    responses = _run_scripted_session(
        [
            {
                "action": "get-databasehash",
                "message": _encrypt(
                    client_sk,
                    host_pk,
                    n1,
                    {"action": "get-databasehash"},
                ),
                "nonce": b64encode(n1),
                "clientID": "e2e",
            }
        ],
        protocol=proto,
    )
    assert len(responses) == 1
    assert responses[0].get("errorCode") == str(ERROR_DATABASE_NOT_OPENED)


def test_e2e_set_login_stub(ka_home: Path) -> None:
    responses = _run_scripted_session(
        [{"action": "set-login", "nonce": b64encode(_nonce_at(0)), "clientID": "e2e"}],
        protocol=KeePassProtocol(fill_request=FakeFill()),
    )
    assert len(responses) == 1
    assert responses[0].get("errorCode") == str(ERROR_INCORRECT_ACTION)
    assert "ka login add" in str(responses[0].get("error"))


def test_e2e_full_framing_including_handshake(ka_home: Path) -> None:
    """Single host session: change-public-keys + associate framed on stdin."""
    fill = FakeFill()
    client_sk = PrivateKey.generate()
    client_pk = b64encode(bytes(client_sk.public_key))
    # Pre-generate host keypair by doing handshake on a throwaway, then rebuild
    # requests for a fresh protocol inside run_host — use two-pass:
    # Pass 1 learns nothing useful across processes; instead encrypt after
    # injecting a protocol that we handshake first, then only frame post-handshake
    # actions (covered above). Here verify change-public-keys framing alone.
    responses = _run_scripted_session(
        [
            {
                "action": "change-public-keys",
                "publicKey": client_pk,
                "nonce": b64encode(_nonce_at(0)),
                "clientID": "e2e",
            }
        ],
        protocol=KeePassProtocol(fill_request=fill),
    )
    assert len(responses) == 1
    assert responses[0]["action"] == "change-public-keys"
    assert responses[0].get("success") == "true"
    assert "publicKey" in responses[0]
