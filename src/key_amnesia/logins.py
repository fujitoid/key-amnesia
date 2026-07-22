"""Login record CRUD and URL host matching (subdomain-suffix).

Domain match: parse hostnames; match if equal or
`request_host.endswith("." + login_host)`. Scheme/port ignored.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from key_amnesia.vault import load_vault, save_vault


class LoginError(Exception):
    """Login CRUD or lookup error."""


def _hostname(url: str) -> str:
    raw = (url or "").strip()
    if not raw:
        return ""
    # urlparse needs a scheme for netloc; treat bare hosts as https://host
    if "://" not in raw:
        raw = "https://" + raw
    host = (urlparse(raw).hostname or "").lower().rstrip(".")
    return host


def hosts_match(request_url: str, login_url: str) -> bool:
    """True if request host equals login host or is a subdomain of it."""
    req = _hostname(request_url)
    stored = _hostname(login_url)
    if not req or not stored:
        return False
    return req == stored or req.endswith("." + stored)


def find_logins_for_url(
    logins: list[dict[str, Any]], url: str
) -> list[dict[str, Any]]:
    """Return login dicts whose host matches *url* (exact or subdomain-suffix)."""
    return [dict(entry) for entry in logins if hosts_match(url, str(entry.get("url") or ""))]


def list_logins(
    path: Path | str | None, password: str
) -> list[dict[str, str]]:
    payload = load_vault(path, password)
    out: list[dict[str, str]] = []
    for entry in payload.get("logins") or []:
        if not isinstance(entry, dict):
            continue
        out.append(
            {
                "url": str(entry.get("url") or ""),
                "username": str(entry.get("username") or ""),
                "secret_name": str(entry.get("secret_name") or ""),
            }
        )
    return out


def add_login(
    path: Path | str | None,
    password: str,
    url: str,
    username: str,
    secret_name: str,
) -> None:
    payload = load_vault(path, password)
    secrets_map = payload.get("secrets") or {}
    if secret_name not in secrets_map:
        raise LoginError(f"unknown secret: {secret_name}")
    logins = list(payload.get("logins") or [])
    for entry in logins:
        if (
            str(entry.get("url") or "") == url
            and str(entry.get("username") or "") == username
        ):
            raise LoginError(f"login already exists for {username} @ {url}")
    logins.append({"url": url, "username": username, "secret_name": secret_name})
    payload["logins"] = logins
    save_vault(path, password, payload)


def remove_login(
    path: Path | str | None,
    password: str,
    url: str,
    username: str,
) -> None:
    payload = load_vault(path, password)
    logins = list(payload.get("logins") or [])
    kept = [
        e
        for e in logins
        if not (
            str(e.get("url") or "") == url
            and str(e.get("username") or "") == username
        )
    ]
    if len(kept) == len(logins):
        raise LoginError(f"no login for {username} @ {url}")
    payload["logins"] = kept
    save_vault(path, password, payload)
