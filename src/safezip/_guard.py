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
_ZIP64_SENTINEL = 0xFFFFFFFF


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
    """Detect ZIP64 inconsistencies and missing ZIP64 blocks.

    Two classes of problem are caught:

    1. **Missing ZIP64 block**: A 32-bit field holds the sentinel value
       ``0xFFFFFFFF`` (meaning "look in ZIP64 extra field"), but no ZIP64
       extra field is present.  This is always a malformed archive.

    2. **Disagreeing ZIP64 block**: A ZIP64 extra field is present, but the
       64-bit value it reports differs from the size that Python's
       ``zipfile`` resolved from the central directory.  A crafted archive
       can set the 32-bit field to a small non-sentinel value while hiding a
       huge size in the ZIP64 block; Python uses the small 32-bit value, but
       we see the discrepancy and reject the archive.
    """
    # Check 1: 32-bit sentinel present but no ZIP64 extra field
    if info.file_size == _ZIP64_SENTINEL or info.compress_size == _ZIP64_SENTINEL:
        zip64 = _parse_zip64_extra(info.extra) if info.extra else {}
        if not zip64:
            raise MalformedArchiveError(
                f"Entry {info.filename!r} has a ZIP64 sentinel (0xFFFFFFFF) "
                f"in the 32-bit size field but no ZIP64 extra field is present. "
                f"Archive is malformed."
            )
        # zip64 is present; fall through to the consistency check below.
        return

    if not info.extra:
        return
    zip64 = _parse_zip64_extra(info.extra)
    if not zip64:
        return

    # Check 2: ZIP64 extra field present but values disagree with resolved sizes
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
