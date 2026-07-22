"""Tests for Native Messaging host installer (workstream B)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from key_amnesia.cli import main as cli_main
from key_amnesia.native_host_install import (
    HOST_NAME,
    build_manifest,
    classify_manifest,
    cmd_install,
    cmd_status,
    cmd_uninstall,
    chromium_manifest,
    firefox_manifest,
    is_our_manifest,
    linux_targets,
    resolve_host_path,
    windows_targets,
)


@pytest.fixture
def host_bin(tmp_path: Path) -> Path:
    path = tmp_path / "bin" / "key-amnesia-browser-host"
    path.parent.mkdir(parents=True)
    path.write_text("#!/bin/sh\n", encoding="utf-8")
    return path.resolve()


@pytest.fixture
def win_roots(tmp_path: Path) -> tuple[Path, Path]:
    local = tmp_path / "Local"
    appdata = tmp_path / "Roaming"
    local.mkdir()
    appdata.mkdir()
    return local, appdata


@pytest.fixture
def linux_home(tmp_path: Path) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    return home


def test_windows_manifest_paths(win_roots: tuple[Path, Path]) -> None:
    local, appdata = win_roots
    targets = windows_targets(local_appdata=local, appdata=appdata)
    by_key = {t.key: t for t in targets}
    assert set(by_key) == {"chrome", "edge", "brave", "firefox"}
    assert by_key["chrome"].manifest_path == (
        local
        / "Google"
        / "Chrome"
        / "User Data"
        / "NativeMessagingHosts"
        / f"{HOST_NAME}.json"
    )
    assert by_key["edge"].manifest_path == (
        local
        / "Microsoft"
        / "Edge"
        / "User Data"
        / "NativeMessagingHosts"
        / f"{HOST_NAME}.json"
    )
    assert by_key["brave"].manifest_path == (
        local
        / "BraveSoftware"
        / "Brave-Browser"
        / "User Data"
        / "NativeMessagingHosts"
        / f"{HOST_NAME}.json"
    )
    assert by_key["firefox"].manifest_path == (
        appdata / "Mozilla" / "NativeMessagingHosts" / f"{HOST_NAME}.json"
    )
    assert by_key["chrome"].family == "chromium"
    assert by_key["firefox"].family == "firefox"
    assert by_key["firefox"].registry_subkey is not None


def test_linux_manifest_paths(linux_home: Path) -> None:
    targets = linux_targets(home=linux_home)
    by_key = {t.key: t for t in targets}
    assert set(by_key) == {"chrome", "chromium", "edge", "brave", "firefox"}
    assert by_key["chrome"].manifest_path == (
        linux_home
        / ".config"
        / "google-chrome"
        / "NativeMessagingHosts"
        / f"{HOST_NAME}.json"
    )
    assert by_key["chromium"].manifest_path == (
        linux_home / ".config" / "chromium" / "NativeMessagingHosts" / f"{HOST_NAME}.json"
    )
    assert by_key["edge"].manifest_path == (
        linux_home
        / ".config"
        / "microsoft-edge"
        / "NativeMessagingHosts"
        / f"{HOST_NAME}.json"
    )
    assert by_key["brave"].manifest_path == (
        linux_home
        / ".config"
        / "BraveSoftware"
        / "Brave-Browser"
        / "NativeMessagingHosts"
        / f"{HOST_NAME}.json"
    )
    assert by_key["firefox"].manifest_path == (
        linux_home / ".mozilla" / "native-messaging-hosts" / f"{HOST_NAME}.json"
    )


def test_manifest_json_shape(host_bin: Path) -> None:
    chrome = chromium_manifest(host_bin)
    assert chrome["name"] == HOST_NAME
    assert chrome["type"] == "stdio"
    assert chrome["path"] == str(host_bin)
    assert chrome["allowed_origins"] == [
        "chrome-extension://oboonakemofpalpdambfdlilmafhnnmo/"
    ]
    assert "allowed_extensions" not in chrome

    ff = firefox_manifest(host_bin)
    assert ff["name"] == HOST_NAME
    assert ff["allowed_extensions"] == ["keepassxc-browser@keepassxc.org"]
    assert "allowed_origins" not in ff


def test_classify_missing_ours_foreign(tmp_path: Path, host_bin: Path) -> None:
    path = tmp_path / f"{HOST_NAME}.json"
    assert classify_manifest(path, host_bin) == ("missing", None)

    write = build_manifest("chromium", host_bin)
    path.write_text(json.dumps(write), encoding="utf-8")
    assert classify_manifest(path, host_bin) == ("ours", None)
    assert is_our_manifest(write, host_bin)

    foreign_host = tmp_path / "keepassxc-proxy"
    foreign_host.write_text("x", encoding="utf-8")
    path.write_text(
        json.dumps(build_manifest("chromium", foreign_host.resolve())),
        encoding="utf-8",
    )
    state, foreign = classify_manifest(path, host_bin)
    assert state == "foreign"
    assert foreign is not None
    assert "keepassxc-proxy" in foreign


def test_install_writes_all_linux_browsers(linux_home: Path, host_bin: Path) -> None:
    targets = linux_targets(home=linux_home)

    rc = cmd_install(
        host_path=host_bin,
        targets=targets,
        platform="linux",
        force=False,
    )
    assert rc == 0
    for t in targets:
        assert t.manifest_path.is_file()
        data = json.loads(t.manifest_path.read_text(encoding="utf-8"))
        assert data["name"] == HOST_NAME
        assert data["path"] == str(host_bin)
        if t.family == "chromium":
            assert "allowed_origins" in data
        else:
            assert "allowed_extensions" in data


def test_install_prints_unlock_note(
    linux_home: Path, host_bin: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = cmd_install(
        host_path=host_bin,
        targets=linux_targets(home=linux_home),
        platform="linux",
    )
    assert rc == 0
    captured = capsys.readouterr()
    combined = captured.out + captured.err
    assert "ka unlock" in combined


def test_collision_never_silent_without_force(
    linux_home: Path, host_bin: Path, tmp_path: Path
) -> None:
    targets = linux_targets(home=linux_home)
    chrome = next(t for t in targets if t.key == "chrome")
    foreign = tmp_path / "other-host"
    foreign.write_text("x", encoding="utf-8")
    chrome.manifest_path.parent.mkdir(parents=True)
    chrome.manifest_path.write_text(
        json.dumps(build_manifest("chromium", foreign.resolve())),
        encoding="utf-8",
    )
    prompts: list[str] = []

    def decline(msg: str) -> bool:
        prompts.append(msg)
        return False

    rc = cmd_install(
        host_path=host_bin,
        targets=[chrome],
        platform="linux",
        force=False,
        confirm_fn=decline,
    )
    assert prompts, "must ask before overwrite"
    data = json.loads(chrome.manifest_path.read_text(encoding="utf-8"))
    assert data["path"] == str(foreign.resolve()), "must not silently overwrite"
    assert rc == 1


def test_collision_force_overwrites(
    linux_home: Path, host_bin: Path, tmp_path: Path
) -> None:
    targets = linux_targets(home=linux_home)
    chrome = next(t for t in targets if t.key == "chrome")
    foreign = tmp_path / "other-host"
    foreign.write_text("x", encoding="utf-8")
    chrome.manifest_path.parent.mkdir(parents=True)
    chrome.manifest_path.write_text(
        json.dumps(build_manifest("chromium", foreign.resolve())),
        encoding="utf-8",
    )

    rc = cmd_install(
        host_path=host_bin,
        targets=[chrome],
        platform="linux",
        force=True,
        confirm_fn=lambda _m: False,  # force should not need yes
    )
    assert rc == 0
    data = json.loads(chrome.manifest_path.read_text(encoding="utf-8"))
    assert data["path"] == str(host_bin)


def test_collision_confirm_yes_overwrites(
    linux_home: Path, host_bin: Path, tmp_path: Path
) -> None:
    chrome = next(t for t in linux_targets(home=linux_home) if t.key == "chrome")
    foreign = tmp_path / "other-host"
    foreign.write_text("x", encoding="utf-8")
    chrome.manifest_path.parent.mkdir(parents=True)
    chrome.manifest_path.write_text(
        json.dumps(build_manifest("chromium", foreign.resolve())),
        encoding="utf-8",
    )

    rc = cmd_install(
        host_path=host_bin,
        targets=[chrome],
        platform="linux",
        force=False,
        confirm_fn=lambda _m: True,
    )
    assert rc == 0
    data = json.loads(chrome.manifest_path.read_text(encoding="utf-8"))
    assert data["path"] == str(host_bin)


def test_status_reports_missing_ours_foreign(
    linux_home: Path, host_bin: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    targets = linux_targets(home=linux_home)
    chrome = next(t for t in targets if t.key == "chrome")
    edge = next(t for t in targets if t.key == "edge")
    brave = next(t for t in targets if t.key == "brave")

    chrome.manifest_path.parent.mkdir(parents=True)
    chrome.manifest_path.write_text(
        json.dumps(build_manifest("chromium", host_bin)), encoding="utf-8"
    )
    foreign = tmp_path / "keepassxc"
    foreign.write_text("x", encoding="utf-8")
    edge.manifest_path.parent.mkdir(parents=True)
    edge.manifest_path.write_text(
        json.dumps(build_manifest("chromium", foreign.resolve())), encoding="utf-8"
    )

    assert classify_manifest(chrome.manifest_path, host_bin)[0] == "ours"
    assert classify_manifest(edge.manifest_path, host_bin)[0] == "foreign"
    assert classify_manifest(brave.manifest_path, host_bin)[0] == "missing"

    rc = cmd_status(host_path=host_bin, targets=[chrome, edge, brave], platform="linux")
    assert rc == 0
    captured = capsys.readouterr()
    text = captured.out + captured.err
    assert "ours" in text
    assert "foreign" in text
    assert "missing" in text
    assert "path=" in text


def test_windows_install_sets_registry(
    win_roots: tuple[Path, Path], host_bin: Path
) -> None:
    local, appdata = win_roots
    targets = windows_targets(local_appdata=local, appdata=appdata)
    registry: dict[str, str] = {}

    rc = cmd_install(
        host_path=host_bin,
        targets=targets,
        platform="win32",
        registry_set=lambda k, v: registry.__setitem__(k, v),
    )
    assert rc == 0
    assert len(registry) == len(targets)
    for t in targets:
        assert t.registry_subkey in registry
        assert registry[t.registry_subkey] == str(t.manifest_path.resolve())
        assert t.manifest_path.is_file()


def test_uninstall_removes_ours_only(
    linux_home: Path, host_bin: Path, tmp_path: Path
) -> None:
    chrome = next(t for t in linux_targets(home=linux_home) if t.key == "chrome")
    edge = next(t for t in linux_targets(home=linux_home) if t.key == "edge")
    chrome.manifest_path.parent.mkdir(parents=True)
    chrome.manifest_path.write_text(
        json.dumps(build_manifest("chromium", host_bin)), encoding="utf-8"
    )
    foreign = tmp_path / "other"
    foreign.write_text("x", encoding="utf-8")
    edge.manifest_path.parent.mkdir(parents=True)
    edge.manifest_path.write_text(
        json.dumps(build_manifest("chromium", foreign.resolve())), encoding="utf-8"
    )

    rc = cmd_uninstall(
        host_path=host_bin,
        targets=[chrome, edge],
        platform="linux",
        force=False,
    )
    assert rc == 0
    assert not chrome.manifest_path.exists()
    assert edge.manifest_path.exists(), "foreign must remain without --force"


def test_macos_fails_closed(host_bin: Path) -> None:
    assert cmd_install(host_path=host_bin, platform="darwin", targets=[]) == 1
    assert cmd_status(host_path=host_bin, platform="darwin", targets=[]) == 1
    assert cmd_uninstall(host_path=host_bin, platform="darwin", targets=[]) == 1


def test_resolve_host_path(host_bin: Path) -> None:
    found = resolve_host_path(which_fn=lambda _name: str(host_bin))
    assert found == host_bin
    assert resolve_host_path(which_fn=lambda _name: None) is None


def test_cli_browser_fill_help() -> None:
    with pytest.raises(SystemExit) as ei:
        cli_main(["browser-fill", "--help"])
    assert ei.value.code == 0
    with pytest.raises(SystemExit) as ei:
        cli_main(["browser-fill", "install", "--help"])
    assert ei.value.code == 0


def test_cli_status_runs(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "Local"))
    monkeypatch.setenv("APPDATA", str(tmp_path / "Roaming"))
    (tmp_path / "Local").mkdir()
    (tmp_path / "Roaming").mkdir()
    monkeypatch.setattr(
        "key_amnesia.native_host_install.resolve_host_path",
        lambda **_k: tmp_path / "missing-host",
    )
    rc = cli_main(["browser-fill", "status"])
    assert rc == 0
