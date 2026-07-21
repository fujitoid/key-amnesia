"""Shared fixtures for key-amnesia tests. Always use tmp_path."""

from __future__ import annotations

import os
from pathlib import Path

import pytest


@pytest.fixture
def ka_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "ka-home"
    home.mkdir()
    monkeypatch.setenv("KEY_AMNESIA_HOME", str(home))
    monkeypatch.delenv("KEY_AMNESIA_VAULT_PATH", raising=False)
    return home


@pytest.fixture
def password() -> str:
    return "test-master-password-敏感"


@pytest.fixture
def seeded_vault(ka_home: Path, password: str) -> Path:
    from key_amnesia.vault import save_vault

    vault = ka_home / "vault.bin"
    save_vault(
        vault,
        password,
        {
            "secrets": {
                "api_key": "super-secret-value-123",
                "db_pass": "p@ssw0rd!.*+?[]{}",
                "token": "tok_abc_xyz",
            },
            "created_at": "2026-01-01T00:00:00+00:00",
            "updated_at": "2026-01-01T00:00:00+00:00",
        },
    )
    return vault
