"""CLI output helpers (Phase 0: plain print; branding lands later)."""

from __future__ import annotations

import sys
from typing import Any


def info(msg: Any = "", **kwargs: Any) -> None:
    kwargs.setdefault("file", sys.stdout)
    print(msg, **kwargs)


def success(msg: Any = "", **kwargs: Any) -> None:
    kwargs.setdefault("file", sys.stdout)
    print(msg, **kwargs)


def warn(msg: Any = "", **kwargs: Any) -> None:
    kwargs.setdefault("file", sys.stderr)
    print(msg, **kwargs)


def error(msg: Any = "", **kwargs: Any) -> None:
    kwargs.setdefault("file", sys.stderr)
    print(msg, **kwargs)


def out(msg: Any = "", **kwargs: Any) -> None:
    kwargs.setdefault("file", sys.stdout)
    print(msg, **kwargs)


def err(msg: Any = "", **kwargs: Any) -> None:
    kwargs.setdefault("file", sys.stderr)
    print(msg, **kwargs)
