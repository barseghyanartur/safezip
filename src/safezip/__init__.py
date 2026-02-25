"""safezip — Hardened ZIP extraction for Python."""

from ._core import SafeZipFile, safe_extract
from ._events import SecurityEvent, SymlinkPolicy
from ._exceptions import (
    CompressionRatioError,
    FileCountExceededError,
    FileSizeExceededError,
    MalformedArchiveError,
    NestingDepthError,
    SafezipError,
    TotalSizeExceededError,
    UnsafeZipError,
)

__title__ = "safezip"
__version__ = "0.1"
__author__ = "Artur Barseghyan <artur.barseghyan@gmail.com>"
__copyright__ = "2026 Artur Barseghyan"
__license__ = "MIT"
__all__ = (
    # Core
    "SafeZipFile",
    "safe_extract",
    # Events / policy
    "SecurityEvent",
    "SymlinkPolicy",
    # Exceptions
    "SafezipError",
    "UnsafeZipError",
    "FileSizeExceededError",
    "TotalSizeExceededError",
    "CompressionRatioError",
    "FileCountExceededError",
    "NestingDepthError",
    "MalformedArchiveError",
)
