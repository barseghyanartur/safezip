"""Phase C: streaming extraction with runtime enforcement (the Streamer)."""

import contextlib
import logging
import os
import zipfile
from pathlib import Path
from typing import Optional

from ._exceptions import (
    CompressionRatioError,
    FileSizeExceededError,
    TotalSizeExceededError,
)

__author__ = "Artur Barseghyan <artur.barseghyan@gmail.com>"
__copyright__ = "2026 Artur Barseghyan"
__license__ = "MIT"
__all__ = (
    "stream_extract_member",
    "CumulativeCounters",
)

log = logging.getLogger("safezip.security")

_CHUNK_SIZE = 65_536  # 64 KiB


class CumulativeCounters:
    """Tracks totals across all members in a single extractall/extract call."""

    __slots__ = ("bytes_written", "compressed_bytes")

    def __init__(self) -> None:
        self.bytes_written: int = 0
        self.compressed_bytes: int = 0


def stream_extract_member(
    zf: zipfile.ZipFile,
    member: zipfile.ZipInfo,
    dest: Path,
    *,
    max_file_size: int,
    max_per_member_ratio: float,
    max_total_size: int,
    max_total_ratio: float,
    counters: CumulativeCounters,
    pwd: Optional[bytes] = None,
) -> None:
    """
    Stream a single member from *zf* to *dest* with full runtime enforcement.

    Extraction is atomic: bytes are written to a temporary file and renamed to
    *dest* only after all checks pass.  If any check raises, the temporary file
    is deleted and *dest* is never created/modified.

    :param zf: Open zipfile.ZipFile instance (internal use only).
    :param member: The ZipInfo entry to extract.
    :param dest: Final destination path (must already be path-validated).
    :param max_file_size: Per-member decompressed size limit in bytes.
    :param max_per_member_ratio: Per-member decompressed/compressed ratio
           limit.
    :param max_total_size: Cumulative decompressed size limit across all
           members.
    :param max_total_ratio: Cumulative ratio limit across all members.
    :param counters: Shared counters for cumulative checks.
    :param pwd: Optional decryption password.
    """
    dest.parent.mkdir(parents=True, exist_ok=True)

    tmp_name = f"{dest.name}.safezip_tmp_{os.getpid()}_{os.urandom(4).hex()}"
    tmp_path = dest.parent / tmp_name

    # O_CREAT | O_EXCL fails if anything, including a symlink, already exists
    # at tmp_path, and never follows it. This happens before the try block so
    # a pre-existing entry is never unlinked by the cleanup below. Mode 0o666
    # keeps the umask-derived permissions that the extracted file inherits.
    fd = os.open(
        tmp_path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
        0o666,
    )

    # compress_size may be 0 for data-descriptor archives
    compress_size = member.compress_size
    member_bytes_written = 0

    try:
        with os.fdopen(fd, "wb") as dst, zf.open(member, pwd=pwd) as src:
            while True:
                chunk = src.read(_CHUNK_SIZE)
                if not chunk:
                    break

                chunk_len = len(chunk)
                member_bytes_written += chunk_len
                counters.bytes_written += chunk_len

                # --- Per-member size check ---
                if member_bytes_written > max_file_size:
                    raise FileSizeExceededError(
                        f"Member {member.filename!r} exceeded max_file_size="
                        f"{max_file_size:,} bytes "
                        f"(decompressed {member_bytes_written:,} bytes so "
                        "far)."
                    )

                # --- Per-member ratio check ---
                # Only when compress_size is known (not a data-descriptor
                # entry).
                if compress_size > 0:
                    ratio = member_bytes_written / compress_size
                    if ratio > max_per_member_ratio:
                        raise CompressionRatioError(
                            f"Member {member.filename!r} compression ratio "
                            f"{ratio:.1f}:1 exceeds "
                            f"max_per_member_ratio={max_per_member_ratio}:1."
                        )

                # --- Cumulative size check ---
                if counters.bytes_written > max_total_size:
                    raise TotalSizeExceededError(
                        f"Cumulative decompressed size "
                        f"{counters.bytes_written:,} bytes exceeds "
                        f"max_total_size={max_total_size:,} bytes."
                    )

                # --- Cumulative ratio check ---
                # Update compressed bytes estimate from the running member.
                if compress_size > 0:
                    counters.compressed_bytes += (
                        chunk_len * compress_size // max(member.file_size, 1)
                    )
                if counters.compressed_bytes > 0:
                    total_ratio = counters.bytes_written / counters.compressed_bytes  # noqa
                    if total_ratio > max_total_ratio:
                        raise CompressionRatioError(
                            f"Cumulative compression ratio {total_ratio:.1f}:1 "
                            f"exceeds max_total_ratio={max_total_ratio}:1."
                        )

                dst.write(chunk)

        # All checks passed - atomic rename to final destination
        tmp_path.replace(dest)

    except Exception:
        # Clean up partial / temporary file on any failure
        with contextlib.suppress(OSError):
            tmp_path.unlink(missing_ok=True)
        raise
