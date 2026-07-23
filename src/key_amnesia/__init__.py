"""key-amnesia: encrypted vault with human-prompt routing and output scrubbing."""

from importlib.metadata import PackageNotFoundError, version as _version

try:
    __version__ = _version("key-amnesia")
except PackageNotFoundError:
    __version__ = "0.0.0"
