"""Install / status / uninstall Native Messaging manifests for browser-fill.

Registers host name ``org.keepassxc.keepassxc_browser`` so the KeePassXC-Browser
extension can find ``key-amnesia-browser-host``. Windows + Linux only; macOS
fails closed.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Literal

from key_amnesia import theme

HOST_NAME = "org.keepassxc.keepassxc_browser"
HOST_DESCRIPTION = "key-amnesia KeePassXC-Browser Native Messaging host"
HOST_SCRIPT = "key-amnesia-browser-host"

CHROMIUM_ALLOWED_ORIGINS = [
    "chrome-extension://oboonakemofpalpdambfdlilmafhnnmo/",
]
FIREFOX_ALLOWED_EXTENSIONS = [
    "keepassxc-browser@keepassxc.org",
]

BrowserFamily = Literal["chromium", "firefox"]
InstallState = Literal["missing", "ours", "foreign", "invalid"]


@dataclass(frozen=True)
class BrowserTarget:
    """One browser × OS install location."""

    key: str
    label: str
    family: BrowserFamily
    manifest_path: Path
    # Windows HKCU relative key under Software\… (None = file-only)
    registry_subkey: str | None = None


ConfirmFn = Callable[[str], bool]
WhichFn = Callable[[str], str | None]
RegistryGetFn = Callable[[str], str | None]
RegistrySetFn = Callable[[str, str], None]
RegistryDeleteFn = Callable[[str], None]


def _platform_name() -> str:
    return sys.platform


def _home() -> Path:
    return Path.home()


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def resolve_host_path(*, which_fn: WhichFn | None = None) -> Path | None:
    """Absolute path to the ``key-amnesia-browser-host`` console script, if found."""
    which = which_fn or shutil.which
    found = which(HOST_SCRIPT)
    if not found:
        return None
    return Path(found).resolve()


def chromium_manifest(host_path: Path) -> dict[str, Any]:
    return {
        "name": HOST_NAME,
        "description": HOST_DESCRIPTION,
        "path": str(host_path),
        "type": "stdio",
        "allowed_origins": list(CHROMIUM_ALLOWED_ORIGINS),
    }


def firefox_manifest(host_path: Path) -> dict[str, Any]:
    return {
        "name": HOST_NAME,
        "description": HOST_DESCRIPTION,
        "path": str(host_path),
        "type": "stdio",
        "allowed_extensions": list(FIREFOX_ALLOWED_EXTENSIONS),
    }


def build_manifest(family: BrowserFamily, host_path: Path) -> dict[str, Any]:
    if family == "firefox":
        return firefox_manifest(host_path)
    return chromium_manifest(host_path)


def windows_targets(
    *,
    local_appdata: Path | None = None,
    appdata: Path | None = None,
) -> list[BrowserTarget]:
    local = local_appdata or Path(
        _env("LOCALAPPDATA") or str(_home() / "AppData" / "Local")
    )
    roaming = appdata or Path(
        _env("APPDATA") or str(_home() / "AppData" / "Roaming")
    )
    name = f"{HOST_NAME}.json"
    return [
        BrowserTarget(
            key="chrome",
            label="Chrome",
            family="chromium",
            manifest_path=local
            / "Google"
            / "Chrome"
            / "User Data"
            / "NativeMessagingHosts"
            / name,
            registry_subkey=rf"Software\Google\Chrome\NativeMessagingHosts\{HOST_NAME}",
        ),
        BrowserTarget(
            key="edge",
            label="Edge",
            family="chromium",
            manifest_path=local
            / "Microsoft"
            / "Edge"
            / "User Data"
            / "NativeMessagingHosts"
            / name,
            registry_subkey=rf"Software\Microsoft\Edge\NativeMessagingHosts\{HOST_NAME}",
        ),
        BrowserTarget(
            key="brave",
            label="Brave",
            family="chromium",
            manifest_path=local
            / "BraveSoftware"
            / "Brave-Browser"
            / "User Data"
            / "NativeMessagingHosts"
            / name,
            registry_subkey=rf"Software\BraveSoftware\Brave-Browser\NativeMessagingHosts\{HOST_NAME}",
        ),
        BrowserTarget(
            key="firefox",
            label="Firefox",
            family="firefox",
            manifest_path=roaming / "Mozilla" / "NativeMessagingHosts" / name,
            registry_subkey=rf"Software\Mozilla\NativeMessagingHosts\{HOST_NAME}",
        ),
    ]


def linux_targets(*, home: Path | None = None) -> list[BrowserTarget]:
    h = home or _home()
    name = f"{HOST_NAME}.json"
    return [
        BrowserTarget(
            key="chrome",
            label="Chrome",
            family="chromium",
            manifest_path=h
            / ".config"
            / "google-chrome"
            / "NativeMessagingHosts"
            / name,
        ),
        BrowserTarget(
            key="chromium",
            label="Chromium",
            family="chromium",
            manifest_path=h / ".config" / "chromium" / "NativeMessagingHosts" / name,
        ),
        BrowserTarget(
            key="edge",
            label="Edge",
            family="chromium",
            manifest_path=h
            / ".config"
            / "microsoft-edge"
            / "NativeMessagingHosts"
            / name,
        ),
        BrowserTarget(
            key="brave",
            label="Brave",
            family="chromium",
            manifest_path=h
            / ".config"
            / "BraveSoftware"
            / "Brave-Browser"
            / "NativeMessagingHosts"
            / name,
        ),
        BrowserTarget(
            key="firefox",
            label="Firefox",
            family="firefox",
            manifest_path=h / ".mozilla" / "native-messaging-hosts" / name,
        ),
    ]


def targets_for_platform(
    platform: str | None = None,
    *,
    home: Path | None = None,
    local_appdata: Path | None = None,
    appdata: Path | None = None,
) -> list[BrowserTarget]:
    plat = platform if platform is not None else _platform_name()
    if plat == "win32":
        return windows_targets(local_appdata=local_appdata, appdata=appdata)
    if plat.startswith("linux"):
        return linux_targets(home=home)
    return []


def _normalize_path(value: str | Path) -> str:
    try:
        return str(Path(value).resolve())
    except OSError:
        return str(value)


def is_our_manifest(data: dict[str, Any], host_path: Path) -> bool:
    """True when manifest ``path`` already points at our host binary."""
    raw = data.get("path")
    if not isinstance(raw, str) or not raw:
        return False
    return _normalize_path(raw) == _normalize_path(host_path)


def classify_manifest(
    path: Path,
    host_path: Path,
) -> tuple[InstallState, str | None]:
    """Return (state, foreign_path_or_None)."""
    if not path.is_file():
        return "missing", None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return "invalid", None
    if not isinstance(data, dict):
        return "invalid", None
    raw = data.get("path")
    if not isinstance(raw, str) or not raw:
        return "invalid", None
    if is_our_manifest(data, host_path):
        return "ours", None
    return "foreign", raw


def _winreg_get(subkey: str) -> str | None:
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, subkey) as key:
            value, _ = winreg.QueryValueEx(key, "")
            return str(value) if value else None
    except OSError:
        return None


def _winreg_set(subkey: str, manifest_path: str) -> None:
    import winreg

    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, subkey) as key:
        winreg.SetValueEx(key, "", 0, winreg.REG_SZ, manifest_path)


def _winreg_delete(subkey: str) -> None:
    import winreg

    try:
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, subkey)
    except FileNotFoundError:
        return
    except OSError:
        # Parent may still hold children; ignore best-effort uninstall noise.
        return


def default_confirm(prompt: str) -> bool:
    try:
        answer = input(f"{prompt} [y/N] ").strip().lower()
    except EOFError:
        return False
    return answer in ("y", "yes")


def write_manifest(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(payload, indent=2, sort_keys=False) + "\n"
    path.write_text(text, encoding="utf-8")


def remove_manifest(path: Path) -> bool:
    if not path.exists():
        return False
    path.unlink()
    return True


def _filter_targets(
    targets: list[BrowserTarget],
    browsers: list[str] | None,
) -> list[BrowserTarget]:
    if not browsers:
        return list(targets)
    wanted = {b.strip().lower() for b in browsers}
    return [t for t in targets if t.key in wanted]


def status_line(target: BrowserTarget, state: InstallState, foreign_path: str | None) -> str:
    if state == "missing":
        detail = "missing"
    elif state == "ours":
        detail = "ours"
    elif state == "foreign":
        detail = f"foreign(path={foreign_path})"
    else:
        detail = "invalid"
    return f"{target.label}: {detail} ({target.manifest_path})"


def cmd_status(
    *,
    host_path: Path | None = None,
    targets: list[BrowserTarget] | None = None,
    platform: str | None = None,
    which_fn: WhichFn | None = None,
) -> int:
    plat = platform if platform is not None else _platform_name()
    if plat == "darwin":
        theme.error(
            "Browser-fill Native Messaging install is not supported on macOS "
            "(Windows and Linux only)."
        )
        return 1

    host = host_path or resolve_host_path(which_fn=which_fn)
    if host is None:
        theme.warn(
            f"Host binary {HOST_SCRIPT!r} not found on PATH; "
            "status still reports manifest files."
        )
        # Use a sentinel so nothing classifies as "ours" without a real path.
        host = Path("__key_amnesia_host_not_found__")

    rows = targets if targets is not None else targets_for_platform(plat)
    if not rows:
        theme.error(f"No browser targets for platform {plat!r}.")
        return 1

    theme.info(f"Native Messaging host: {HOST_NAME}")
    if host.name != "__key_amnesia_host_not_found__":
        theme.info(f"Expected host path: {host}")
    for target in rows:
        state, foreign = classify_manifest(target.manifest_path, host)
        line = status_line(target, state, foreign)
        if state == "ours":
            theme.success(line)
        elif state in ("foreign", "invalid"):
            theme.warn(line)
        else:
            theme.out(line)
    return 0


def cmd_install(
    *,
    force: bool = False,
    browsers: list[str] | None = None,
    host_path: Path | None = None,
    targets: list[BrowserTarget] | None = None,
    platform: str | None = None,
    which_fn: WhichFn | None = None,
    confirm_fn: ConfirmFn | None = None,
    registry_get: RegistryGetFn | None = None,
    registry_set: RegistrySetFn | None = None,
) -> int:
    plat = platform if platform is not None else _platform_name()
    if plat == "darwin":
        theme.error(
            "Browser-fill Native Messaging install is not supported on macOS "
            "(Windows and Linux only)."
        )
        return 1

    host = host_path or resolve_host_path(which_fn=which_fn)
    if host is None:
        theme.error(
            f"Could not find {HOST_SCRIPT!r} on PATH. "
            "Install the package first (pip install .) then retry."
        )
        return 1

    rows = _filter_targets(
        targets if targets is not None else targets_for_platform(plat),
        browsers,
    )
    if not rows:
        theme.error("No matching browser targets.")
        return 1

    confirm = confirm_fn or default_confirm
    reg_set = registry_set
    if plat == "win32" and reg_set is None:
        reg_set = _winreg_set

    installed = 0
    skipped = 0
    for target in rows:
        payload = build_manifest(target.family, host)
        state, foreign = classify_manifest(target.manifest_path, host)

        if state == "ours":
            theme.info(f"{target.label}: already installed ({target.manifest_path})")
            if plat == "win32" and target.registry_subkey and reg_set is not None:
                reg_set(target.registry_subkey, str(target.manifest_path.resolve()))
            installed += 1
            continue

        if state in ("foreign", "invalid"):
            theme.warn(
                f"{target.label}: existing Native Messaging host "
                f"{HOST_NAME!r} at {target.manifest_path}"
                + (f" (path={foreign})" if foreign else " (unreadable/invalid)")
            )
            theme.warn(
                "Overwriting will replace KeePassXC (or another app) as the "
                "Native Messaging host for this extension. Never done silently."
            )
            if not force:
                if not confirm(f"Overwrite {target.label} manifest?"):
                    theme.info(f"{target.label}: skipped (left untouched)")
                    skipped += 1
                    continue
            else:
                theme.warn(f"{target.label}: --force set; overwriting")

        write_manifest(target.manifest_path, payload)
        if plat == "win32" and target.registry_subkey and reg_set is not None:
            reg_set(target.registry_subkey, str(target.manifest_path.resolve()))
        theme.success(f"{target.label}: installed → {target.manifest_path}")
        installed += 1

    theme.info(
        f"Done: {installed} installed/updated, {skipped} skipped. "
        "Run `ka unlock` before the extension can retrieve logins."
    )
    return 0 if installed > 0 or skipped == 0 else 1


def cmd_uninstall(
    *,
    browsers: list[str] | None = None,
    host_path: Path | None = None,
    targets: list[BrowserTarget] | None = None,
    platform: str | None = None,
    which_fn: WhichFn | None = None,
    force: bool = False,
    confirm_fn: ConfirmFn | None = None,
    registry_delete: RegistryDeleteFn | None = None,
) -> int:
    plat = platform if platform is not None else _platform_name()
    if plat == "darwin":
        theme.error(
            "Browser-fill Native Messaging install is not supported on macOS "
            "(Windows and Linux only)."
        )
        return 1

    host = host_path or resolve_host_path(which_fn=which_fn)
    if host is None:
        host = Path("__key_amnesia_host_not_found__")

    rows = _filter_targets(
        targets if targets is not None else targets_for_platform(plat),
        browsers,
    )
    if not rows:
        theme.error("No matching browser targets.")
        return 1

    confirm = confirm_fn or default_confirm
    reg_del = registry_delete
    if plat == "win32" and reg_del is None:
        reg_del = _winreg_delete

    removed = 0
    for target in rows:
        state, foreign = classify_manifest(target.manifest_path, host)
        if state == "missing":
            theme.out(f"{target.label}: nothing to remove")
            continue
        if state == "foreign" and not force:
            theme.warn(
                f"{target.label}: foreign host at {target.manifest_path} "
                f"(path={foreign}); refusing to delete without --force"
            )
            continue
        if state == "foreign" and force:
            if not confirm(f"Delete foreign {target.label} manifest?"):
                theme.info(f"{target.label}: skipped")
                continue
        remove_manifest(target.manifest_path)
        if plat == "win32" and target.registry_subkey and reg_del is not None:
            reg_del(target.registry_subkey)
        theme.success(f"{target.label}: removed {target.manifest_path}")
        removed += 1

    theme.info(f"Uninstall complete ({removed} removed).")
    return 0


def build_browser_fill_parser(sub: Any) -> argparse.ArgumentParser:
    """Register `ka browser-fill` and its subcommands on the root subparsers."""
    p = sub.add_parser(
        "browser-fill",
        help="Install or inspect KeePassXC-Browser Native Messaging host",
    )
    bf_sub = p.add_subparsers(dest="browser_fill_command")

    install_p = bf_sub.add_parser(
        "install",
        help="Install native messaging manifests (Chrome/Edge/Brave/Firefox)",
    )
    install_p.add_argument(
        "--force",
        action="store_true",
        help="Overwrite an existing foreign host manifest without prompting",
    )
    install_p.add_argument(
        "--browser",
        action="append",
        dest="browsers",
        metavar="NAME",
        help=(
            "Limit to one browser key (repeatable): "
            "chrome, edge, brave, firefox[, chromium]"
        ),
    )

    bf_sub.add_parser("status", help="Show per-browser install status")

    uninstall_p = bf_sub.add_parser(
        "uninstall",
        help="Remove key-amnesia native messaging manifests",
    )
    uninstall_p.add_argument(
        "--force",
        action="store_true",
        help="Also remove a foreign host manifest after confirmation",
    )
    uninstall_p.add_argument(
        "--browser",
        action="append",
        dest="browsers",
        metavar="NAME",
        help="Limit to one browser key (repeatable)",
    )
    return p


def main(args: argparse.Namespace) -> int:
    """Dispatch ``ka browser-fill`` subcommands."""
    cmd = getattr(args, "browser_fill_command", None)
    if cmd is None:
        theme.error("Usage: ka browser-fill {install|status|uninstall} …")
        return 2
    if cmd == "status":
        return cmd_status()
    if cmd == "install":
        return cmd_install(
            force=bool(getattr(args, "force", False)),
            browsers=getattr(args, "browsers", None),
        )
    if cmd == "uninstall":
        return cmd_uninstall(
            force=bool(getattr(args, "force", False)),
            browsers=getattr(args, "browsers", None),
        )
    theme.error(f"Unknown browser-fill command: {cmd}")
    return 2
