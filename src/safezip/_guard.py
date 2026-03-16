"""Phase A: pre-extraction static validation (the Guard)."""

import os
import struct
import zipfile
from dataclasses import dataclass
from typing import BinaryIO, Optional

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


@dataclass
class ScanResult:
    """Three-valued outcome of inspecting a zip file for overlapping records."""

    is_bomb: Optional[bool]
    invalid_reason: Optional[str] = None
    overlap_detail: Optional[str] = None

    @classmethod
    def clean(cls) -> "ScanResult":
        return cls(is_bomb=False)

    @classmethod
    def bomb(cls, detail: str) -> "ScanResult":
        return cls(is_bomb=True, overlap_detail=detail)

    @classmethod
    def invalid(cls, reason: str) -> "ScanResult":
        return cls(is_bomb=None, invalid_reason=reason)


class ZipInspector:
    """Parses a zip file's structural records and checks for overlapping spans.

    Based on the approach described in David Fifield's zip bomb research:
    https://www.bamsoftware.com/hacks/zipbomb/
    """

    _SEARCH_BLOCK = 8192

    def __init__(self, fileobj: BinaryIO, verbose: bool = False) -> None:
        self._fobj = fileobj
        self._verbose = verbose
        self._file_size: int = 0
        self._record_spans: list[tuple[int, int]] = []

    def scan(self) -> ScanResult:
        """Inspect the zip file and return a ScanResult."""
        self._fobj.seek(0, os.SEEK_END)
        self._file_size = self._fobj.tell()
        self._record_spans = []

        directory = self._locate_central_directory()
        if directory is None:
            return ScanResult.invalid("could not locate a valid central directory")

        num_entries, cd_byte_length, cd_offset = directory
        local_spans = self._walk_central_directory(
            num_entries, cd_byte_length, cd_offset
        )
        if local_spans is None:
            return ScanResult.invalid(
                "central directory parse error or unsupported feature"
            )

        return self._check_spans(local_spans)

    def _locate_central_directory(self) -> Optional[tuple[int, int, int]]:
        """Scan backwards through the file for a valid EOCD record."""
        block = self._SEARCH_BLOCK
        cursor = self._file_size
        readback = 22
        carry = b""
        check_count = 1

        while True:
            cursor -= readback
            if cursor < 0:
                return None

            self._fobj.seek(cursor, os.SEEK_SET)
            window = self._fobj.read(readback) + carry[:21]

            while check_count > 0:
                check_count -= 1
                if (
                    window[check_count] == 0x50
                    and window[check_count + 1] == 0x4B
                    and window[check_count + 2] == 0x05
                    and window[check_count + 3] == 0x06
                ):
                    result = self._validate_eocd(
                        window[check_count + 4 : check_count + 22],
                        cursor + check_count,
                    )
                    if result is not None:
                        return result

            carry = window
            readback = ((cursor - 1) & (block - 1)) + 1
            check_count = readback

    def _validate_eocd(
        self, eocd_body: bytes, eocd_offset: int
    ) -> Optional[tuple[int, int, int]]:
        """Validate the EOCD record and handle Zip64 when needed."""
        if len(eocd_body) < 18:
            return None

        raw = struct.unpack("<HHHHLLH", eocd_body)
        disk_num, cd_start_disk, *_, comment_len = raw

        if disk_num != 0 or cd_start_disk != 0:
            return None
        if eocd_offset + 22 + comment_len > self._file_size:
            return None

        spans_scratch: list[tuple[int, int]] = [
            (eocd_offset, eocd_offset + 22 + comment_len)
        ]

        entries_on_disk, total_entries, cd_length, cd_offset = raw[2:6]

        if (
            entries_on_disk == 0xFFFF
            or total_entries == 0xFFFF
            or cd_length == 0xFFFFFFFF
            or cd_offset == 0xFFFFFFFF
        ):
            z64 = self._read_zip64_records(eocd_offset, spans_scratch)
            if z64 is None:
                return None
            total_entries, cd_length, cd_offset = z64
        else:
            if total_entries != entries_on_disk:
                return None
            if cd_offset + cd_length > self._file_size:
                return None

        spans_scratch.append((cd_offset, cd_offset + cd_length))
        spans_scratch.reverse()
        self._record_spans.extend(spans_scratch)
        return (total_entries, cd_length, cd_offset)

    def _read_zip64_records(
        self,
        eocd_offset: int,
        spans_scratch: list[tuple[int, int]],
    ) -> Optional[tuple[int, int, int]]:
        """Read the Zip64 locator and record."""
        if eocd_offset < 20:
            return None

        self._fobj.seek(eocd_offset - 20, os.SEEK_SET)
        loc_sig, loc_disk, z64_eocd_offset, loc_total_disks = struct.unpack(
            "<LLQL", self._fobj.read(20)
        )
        if (
            loc_sig != 0x07064B50
            or loc_disk != 0
            or loc_total_disks != 1
            or z64_eocd_offset + 56 > self._file_size
        ):
            return None

        spans_scratch.append((eocd_offset - 20, eocd_offset))

        self._fobj.seek(z64_eocd_offset, os.SEEK_SET)
        z64 = struct.unpack("<LQHHLLQQQQ", self._fobj.read(56))
        z64_sig, z64_record_size, _, _, z64_disk, z64_cd_disk, *rest = z64
        if (
            z64_sig != 0x06064B50
            or z64_record_size < 44
            or z64_disk != 0
            or z64_cd_disk != 0
        ):
            return None

        spans_scratch.append((z64_eocd_offset, z64_eocd_offset + 12 + z64_record_size))

        total_entries, _, cd_length, cd_offset = rest
        return (total_entries, cd_length, cd_offset)

    def _walk_central_directory(
        self, num_entries: int, cd_byte_length: int, cd_offset: int
    ) -> Optional[list[tuple[int, int]]]:
        """Read every central directory header and resolve to local entry spans."""
        self._fobj.seek(cd_offset, os.SEEK_SET)
        cd_bytes = self._fobj.read(cd_byte_length)

        local_spans: list[tuple[int, int]] = []
        cursor = 0
        remaining = num_entries

        while remaining > 0:
            if cursor + 46 > cd_byte_length:
                return None

            span = self._parse_cdh_entry(cd_bytes, cursor, cd_byte_length)
            if span is None:
                return None

            entry_span, next_cursor = span
            local_spans.append(entry_span)
            cursor = next_cursor
            remaining -= 1

        if cursor != cd_byte_length:
            return None
        return local_spans

    def _parse_cdh_entry(
        self, cd_bytes: bytes, offset: int, cd_length: int
    ) -> Optional[tuple[tuple[int, int], int]]:
        """Parse one central directory header and return local span."""
        hdr = struct.unpack("<LHHHHHHLLLHHHHHLL", cd_bytes[offset : offset + 46])
        offset += 46

        if hdr[0] != 0x02014B50:
            return None

        fname_len, extra_len, comment_len = hdr[10], hdr[11], hdr[12]
        total_variable = fname_len + extra_len + comment_len
        if offset + total_variable > cd_length:
            return None

        compressed_size = hdr[8]
        uncompressed_size = hdr[9]
        disk_number = hdr[13]
        local_hdr_offset = hdr[16]

        if (
            compressed_size == 0xFFFFFFFF
            or uncompressed_size == 0xFFFFFFFF
            or disk_number == 0xFFFF
            or local_hdr_offset == 0xFFFFFFFF
        ):
            z64_result = self._resolve_zip64_cdh_fields(
                cd_bytes,
                offset + fname_len,
                offset + fname_len + extra_len,
                compressed_size,
                uncompressed_size,
                disk_number,
                local_hdr_offset,
            )
            if z64_result is None:
                return None
            (
                compressed_size,
                uncompressed_size,
                disk_number,
                local_hdr_offset,
            ) = z64_result
            offset += fname_len + extra_len + comment_len
        else:
            offset += total_variable

        if disk_number != 0:
            return None
        if local_hdr_offset + 30 > self._file_size:
            return None

        local_end = self._measure_local_entry(
            local_hdr_offset,
            compressed_size,
            uncompressed_size,
            hdr[7],
        )
        if local_end is None:
            return None

        return ((local_hdr_offset, local_end), offset)

    @staticmethod
    def _resolve_zip64_cdh_fields(
        cd_bytes: bytes,
        extra_start: int,
        extra_end: int,
        compressed_size: int,
        uncompressed_size: int,
        disk_number: int,
        local_hdr_offset: int,
    ) -> Optional[tuple[int, int, int, int]]:
        """Walk the extra field looking for Zip64 extended information block."""
        pos = extra_start
        while pos + 4 <= extra_end:
            field_id, field_data_len = struct.unpack("<HH", cd_bytes[pos : pos + 4])
            pos += 4
            if pos + field_data_len > extra_end:
                return None
            field_end = pos + field_data_len

            if field_id != 0x0001:
                pos = field_end
                continue

            if uncompressed_size == 0xFFFFFFFF:
                if pos + 8 > field_end:
                    return None
                uncompressed_size = struct.unpack("<Q", cd_bytes[pos : pos + 8])[0]
                pos += 8
            if compressed_size == 0xFFFFFFFF:
                if pos + 8 > field_end:
                    return None
                compressed_size = struct.unpack("<Q", cd_bytes[pos : pos + 8])[0]
                pos += 8
            if local_hdr_offset == 0xFFFFFFFF:
                if pos + 8 > field_end:
                    return None
                local_hdr_offset = struct.unpack("<Q", cd_bytes[pos : pos + 8])[0]
                pos += 8
            if disk_number == 0xFFFF:
                if pos + 4 > field_end:
                    return None
                disk_number = struct.unpack("<L", cd_bytes[pos : pos + 4])[0]
                pos += 4

            if pos != field_end:
                return None

            return (compressed_size, uncompressed_size, disk_number, local_hdr_offset)

        return None

    def _measure_local_entry(
        self,
        local_offset: int,
        compressed_size: int,
        uncompressed_size: int,
        expected_crc: int,
    ) -> Optional[int]:
        """Read the local file header and return the byte offset after this entry."""
        self._fobj.seek(local_offset, os.SEEK_SET)
        raw = self._fobj.read(30)
        if len(raw) < 30:
            return None

        lfh = struct.unpack("<LHHHHHLLLHH", raw)
        if lfh[0] != 0x04034B50:
            return None

        fname_len, extra_len = lfh[9], lfh[10]
        flags = lfh[2]

        entry_end = local_offset + 30 + fname_len + extra_len + compressed_size
        if entry_end > self._file_size:
            return None

        if flags & 0x08:
            descriptor_end = self._measure_data_descriptor(
                entry_end, expected_crc, compressed_size, uncompressed_size
            )
            if descriptor_end is None:
                return None
            entry_end = descriptor_end

        return entry_end

    def _measure_data_descriptor(
        self,
        descriptor_offset: int,
        expected_crc: int,
        compressed_size: int,
        uncompressed_size: int,
    ) -> Optional[int]:
        """Determine the extent of the optional data descriptor."""
        self._fobj.seek(descriptor_offset, os.SEEK_SET)
        raw = self._fobj.read(24)

        if len(raw) == 24:
            d = struct.unpack("<LLQQ", raw)
            if (
                d[0] == 0x08074B50
                and d[1] == expected_crc
                and d[2] == compressed_size
                and d[3] == uncompressed_size
            ):
                return descriptor_offset + 24

        if len(raw) >= 20:
            d = struct.unpack("<LQQ", raw[:20])
            if (
                d[0] == expected_crc
                and d[1] == compressed_size
                and d[2] == uncompressed_size
            ):
                return descriptor_offset + 20

        if len(raw) >= 16:
            d = struct.unpack("<LLLL", raw[:16])
            if (
                d[0] == 0x08074B50
                and d[1] == expected_crc
                and d[2] == compressed_size
                and d[3] == uncompressed_size
            ):
                return descriptor_offset + 16

        if len(raw) >= 12:
            d = struct.unpack("<LLL", raw[:12])
            if (
                d[0] == expected_crc
                and d[1] == compressed_size
                and d[2] == uncompressed_size
            ):
                return descriptor_offset + 12

        return None

    def _check_spans(self, local_spans: list[tuple[int, int]]) -> ScanResult:
        """Merge local entry spans with structural spans and scan for overlaps."""
        all_spans = local_spans + self._record_spans
        all_spans.sort()

        _, prev_end = all_spans[0]

        for span_start, span_end in all_spans[1:]:
            if prev_end > span_start:
                return ScanResult.bomb(
                    f"records overlap: previous ends at {prev_end}, "
                    f"next starts at {span_start}"
                )
            prev_end = span_end

        return ScanResult.clean()


def _check_overlapping_entries(fileobj) -> None:
    """Detect Fifield-style zip bombs using ZipInspector.

    :param fileobj: A seekable binary file object.
    :raises MalformedArchiveError: If overlapping entries are detected.
    """
    result = ZipInspector(fileobj).scan()
    if result.is_bomb is True:
        raise MalformedArchiveError(
            "Archive contains overlapping local entries — "
            "likely a Fifield-style zip bomb. Extraction refused."
        )


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
        # A ZIP64 block is present.  Python's zipfile should have already
        # replaced info.file_size / info.compress_size with the resolved
        # 64-bit values, so the sentinel should no longer appear in those
        # fields when we reach Check 2.  Running Check 2 here would produce
        # a false positive (ZIP64 value ≠ sentinel), so we stop.
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

    if zf.fp is not None:
        _check_overlapping_entries(zf.fp)

    for info in entries:
        _validate_entry(info, max_file_size)
