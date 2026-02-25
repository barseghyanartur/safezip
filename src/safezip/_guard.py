"""Phase A: pre-extraction static validation (the Guard)."""

import struct
import zipfile

from ._exceptions import (
    FileCountExceededError,
    FileSizeExceededError,
    MalformedArchiveError,
)

__author__ = "Artur Barseghyan <artur.barseghyan@gmail.com>"
__copyright__ = "2026 Artur Barseghyan"
__license__ = "MIT"
__all__ = ("validate_archive",)

_ZIP64_EXTRA_TAG = 0x0001


def _parse_zip64_extra(extra_bytes: bytes) -> dict:
    """Parse the ZIP64 extended information extra field (tag 0x0001).

    Returns a dict with any of the keys:
      'uncompressed_size', 'compressed_size', 'local_header_offset'
    """
    result: dict = {}
    offset = 0
    while offset + 4 <= len(extra_bytes):
        try:
            tag, size = struct.unpack_from("<HH", extra_bytes, offset)
        except struct.error:
            break
        offset += 4
        if tag == _ZIP64_EXTRA_TAG:
            data = extra_bytes[offset : offset + size]
            pos = 0
            if len(data) >= 8:
                result["uncompressed_size"] = struct.unpack_from("<Q", data, pos)[0]
                pos += 8
            if len(data) >= pos + 8:
                result["compressed_size"] = struct.unpack_from("<Q", data, pos)[0]
                pos += 8
            if len(data) >= pos + 8:
                result["local_header_offset"] = struct.unpack_from("<Q", data, pos)[0]
            break
        offset += size
    return result


def _check_zip64_consistency(info: zipfile.ZipInfo) -> None:
    """Detect ZIP64 extra fields that disagree with Python's resolved sizes.

    Python's zipfile uses the ZIP64 value only when the 32-bit sentinel
    (0xFFFFFFFF) is set.  A crafted archive can include a ZIP64 block with a
    near-max value while keeping the 32-bit fields at a small non-sentinel
    number; Python then uses the 32-bit value, but our parser sees the huge
    ZIP64 value - a clear inconsistency.
    """
    if not info.extra:
        return
    zip64 = _parse_zip64_extra(info.extra)
    if not zip64:
        return

    if "uncompressed_size" in zip64 and zip64["uncompressed_size"] != info.file_size:
        raise MalformedArchiveError(
            f"ZIP64 inconsistency in entry {info.filename!r}: "
            f"extra field reports uncompressed_size="
            f"{zip64['uncompressed_size']}, "
            f"but central directory reports {info.file_size}. "
            f"Archive may be crafted."
        )

    if "compressed_size" in zip64 and zip64["compressed_size"] != info.compress_size:
        raise MalformedArchiveError(
            f"ZIP64 inconsistency in entry {info.filename!r}: "
            f"extra field reports compressed_size="
            f"{zip64['compressed_size']}, "
            f"but central directory reports {info.compress_size}. "
            f"Archive may be crafted."
        )


def _validate_entry(info: zipfile.ZipInfo, max_file_size: int) -> None:
    """Validate a single ZipInfo entry during the Guard phase."""
    # Null bytes in filename
    if "\x00" in info.filename:
        raise MalformedArchiveError(
            f"Entry filename contains a null byte: {info.filename!r}"
        )

    # ZIP64 consistency
    _check_zip64_consistency(info)

    # Declared size early-rejection (Streamer enforces at stream time too)
    if info.file_size > max_file_size:
        raise FileSizeExceededError(
            f"Entry {info.filename!r} declares uncompressed size "
            f"{info.file_size:,} bytes, which exceeds the limit of "
            f"{max_file_size:,} bytes."
        )


def validate_archive(
    zf: zipfile.ZipFile,
    max_files: int,
    max_file_size: int,
) -> None:
    """Phase A: run all pre-extraction static checks.

    :param zf: An open zipfile.ZipFile instance (read-only access).
    :param max_files: Maximum number of entries permitted.
    :param max_file_size: Maximum permitted uncompressed size for any entry.
    :raises FileCountExceededError: If the archive has too many entries.
    :raises FileSizeExceededError: If any entry's declared size is too large.
    :raises MalformedArchiveError: If structural anomalies are detected.
    """
    try:
        entries = zf.infolist()
    except Exception as exc:
        raise MalformedArchiveError(f"Cannot read central directory: {exc}") from exc

    if len(entries) > max_files:
        raise FileCountExceededError(
            f"Archive contains {len(entries):,} entries, "
            f"which exceeds the limit of {max_files:,}."
        )

    for info in entries:
        _validate_entry(info, max_file_size)
