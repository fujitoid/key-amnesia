"""Login CRUD and subdomain-suffix URL matching."""

from __future__ import annotations

from pathlib import Path

import pytest

from key_amnesia.logins import (
    LoginError,
    add_login,
    find_logins_for_url,
    hosts_match,
    list_logins,
    remove_login,
)
from key_amnesia.vault import empty_payload, load_vault


def test_empty_payload_has_logins_schema() -> None:
    p = empty_payload()
    assert p["logins"] == []
    assert p["browser_associations"] == []
    assert isinstance(p["database_id"], str) and len(p["database_id"]) >= 32


def test_load_defaults_missing_logins(ka_home: Path, password: str) -> None:
    import json
    import struct

    from key_amnesia import crypto
    from key_amnesia.vault import HEADER_FMT, MAGIC, VERSION, load_vault

    vault = ka_home / "vault.bin"
    salt = crypto.generate_salt()
    key = crypto.derive_key(
        password.encode("utf-8"),
        salt,
        opslimit=crypto.OPSLIMIT,
        memlimit=crypto.MEMLIMIT,
    )
    legacy = {
        "secrets": {"x": "y"},
        "created_at": "2026-01-01T00:00:00+00:00",
        "updated_at": "2026-01-01T00:00:00+00:00",
    }
    blob = crypto.encrypt(key, json.dumps(legacy).encode("utf-8"))
    header = struct.pack(
        HEADER_FMT, MAGIC, VERSION, salt, crypto.OPSLIMIT, crypto.MEMLIMIT
    )
    vault.write_bytes(header + blob)
    loaded = load_vault(vault, password)
    assert loaded["logins"] == []
    assert loaded["browser_associations"] == []
    assert loaded["database_id"]


def test_hosts_match_exact_and_subdomain() -> None:
    assert hosts_match("https://example.com/login", "https://example.com")
    assert hosts_match("https://app.example.com/x", "https://example.com")
    assert hosts_match("http://app.example.com:8443/", "example.com")
    assert not hosts_match("https://evil.com", "https://example.com")
    assert not hosts_match("https://example.com.evil.com", "https://example.com")
    assert not hosts_match("https://notexample.com", "https://example.com")


def test_find_logins_for_url_filters() -> None:
    logins = [
        {"url": "https://example.com", "username": "a", "secret_name": "s1"},
        {"url": "https://other.org", "username": "b", "secret_name": "s2"},
    ]
    found = find_logins_for_url(logins, "https://www.example.com/path")
    assert len(found) == 1
    assert found[0]["username"] == "a"
    assert find_logins_for_url(logins, "https://nope.test") == []


def test_login_crud(seeded_vault: Path, password: str) -> None:
    add_login(None, password, "https://example.com", "alice", "api_key")
    listed = list_logins(None, password)
    assert listed == [
        {
            "url": "https://example.com",
            "username": "alice",
            "secret_name": "api_key",
        }
    ]
    with pytest.raises(LoginError, match="already exists"):
        add_login(None, password, "https://example.com", "alice", "api_key")
    with pytest.raises(LoginError, match="unknown secret"):
        add_login(None, password, "https://example.com", "bob", "missing")
    remove_login(None, password, "https://example.com", "alice")
    assert list_logins(None, password) == []
    with pytest.raises(LoginError, match="no login"):
        remove_login(None, password, "https://example.com", "alice")
