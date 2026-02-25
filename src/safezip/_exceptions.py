"""Exception hierarchy for safezip."""

__author__ = "Artur Barseghyan <artur.barseghyan@gmail.com>"
__copyright__ = "2026 Artur Barseghyan"
__license__ = "MIT"
__all__ = (
    "SafezipError",
    "UnsafeZipError",
    "FileSizeExceededError",
    "TotalSizeExceededError",
    "CompressionRatioError",
    "FileCountExceededError",
    "NestingDepthError",
    "MalformedArchiveError",
)


class SafezipError(Exception):
    """Base class for all safezip security exceptions."""


class UnsafeZipError(SafezipError):
    """Path traversal, absolute paths, or disallowed symlinks detected."""


class FileSizeExceededError(SafezipError):
    """A single member's decompressed size exceeds max_file_size."""


class TotalSizeExceededError(SafezipError):
    """Cumulative decompressed size across all members exceeds max_total_size."""


class CompressionRatioError(SafezipError):
    """Compression ratio exceeds the configured limit (per-member or total)."""


class FileCountExceededError(SafezipError):
    """Archive entry count exceeds max_files."""


class NestingDepthError(SafezipError):
    """Nested archive depth exceeds max_nesting_depth."""


class MalformedArchiveError(SafezipError):
    """Archive is structurally invalid (ZIP64 inconsistency, count mismatch, etc.)."""
