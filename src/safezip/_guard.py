"""Phase A: pre-extraction static validation (the Guard)."""

import logging
import mmap
import os
import struct
import tempfile
import zipfile
from contextlib import suppress
from dataclasses import dataclass, field
from typing import IO, BinaryIO, List, Optional, Tuple

from ._exceptions import (
    FileCountExceededError,
    FileSizeExceededError,
    MalformedArchiveError,
)

log = logging.getLogger("safezip.security")

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


# ---------------------------------------------------------------------------
# Comprehensive Zip Bomb Detection (Fifield 2019)
# ---------------------------------------------------------------------------

ZIP64_EXTRA_ID = 0x0001
COMPRESS_STORED = 0
COMPRESS_DEFLATE = 8
COMPRESS_BZIP2 = 12
SENTINEL_32 = 0xFFFFFFFF
SENTINEL_16 = 0xFFFF


@dataclass
class Config:
    max_aggregate_ratio: float = 10000.0  # Very high; let Streamer handle ratio checks
    max_total_uncompressed_bytes: int = (
        10 * 1024**3
    )  # 10 GiB; above SafeZipFile default
    max_file_count: int = 100_000  # Above SafeZipFile default of 10_000
    max_deflate_ratio: float = 1_032.0
    max_bzip2_ratio: float = 1_434_375.0


@dataclass
class FileEntry:
    filename: str
    header_offset: int
    compressed_size: int
    uncompressed_size: int
    compress_type: int
    cdh_extra_len: int = 0
    lfh_extra_len: int = -1
    data_start: int = 0
    data_end: int = 0


@dataclass
class Issue:
    kind: str
    detail: str


@dataclass
class DetectionResult:
    is_bomb: bool = False
    issues: List[Issue] = field(default_factory=list)
    compression_ratio: float = 0.0
    total_uncompressed: int = 0
    file_count: int = 0
    zip_size: int = 0
    zip64: bool = False


def _find_eocd(mm: mmap.mmap, file_size: int) -> int:
    sig = b"PK\x05\x06"
    search_start = max(0, file_size - 65535 - 22)
    mm.seek(search_start)
    tail = mm.read(file_size - search_start)
    pos = tail.rfind(sig)
    return search_start + pos if pos != -1 else -1


def _read_eocd(mm: mmap.mmap, file_size: int) -> Tuple[int, int, bool]:
    eocd_pos = _find_eocd(mm, file_size)
    if eocd_pos == -1:
        raise ValueError("No End of Central Directory record found")

    mm.seek(eocd_pos)
    eocd = mm.read(22)
    if len(eocd) < 22:
        raise ValueError("Truncated EOCD")

    cd_count_16 = struct.unpack_from("<H", eocd, 8)[0]
    cd_offset_32 = struct.unpack_from("<I", eocd, 16)[0]

    if eocd_pos >= 20:
        mm.seek(eocd_pos - 20)
        locator = mm.read(20)
        if locator[:4] == b"PK\x06\x07":
            zip64_eocd_offset = struct.unpack_from("<Q", locator, 8)[0]
            mm.seek(zip64_eocd_offset)
            eocd64 = mm.read(56)
            if len(eocd64) >= 56 and eocd64[:4] == b"PK\x06\x06":
                cd_count_64 = struct.unpack_from("<Q", eocd64, 32)[0]
                cd_offset_64 = struct.unpack_from("<Q", eocd64, 48)[0]
                return cd_offset_64, cd_count_64, True

    return cd_offset_32, cd_count_16, False


def _parse_zip64_extra(extra_bytes: bytes) -> dict:
    result: dict = {}
    i = 0
    while i + 4 <= len(extra_bytes):
        hdr_id = struct.unpack_from("<H", extra_bytes, i)[0]
        data_len = struct.unpack_from("<H", extra_bytes, i + 2)[0]
        i += 4
        if hdr_id == ZIP64_EXTRA_ID:
            j = i
            if j + 8 <= i + data_len:
                result["uncompressed_size"] = struct.unpack_from("<Q", extra_bytes, j)[
                    0
                ]
                j += 8
            if j + 8 <= i + data_len:
                result["compressed_size"] = struct.unpack_from("<Q", extra_bytes, j)[0]
                j += 8
            if j + 8 <= i + data_len:
                result["header_offset"] = struct.unpack_from("<Q", extra_bytes, j)[0]
            break
        i += data_len
    return result


def parse_central_directory(
    mm: mmap.mmap, file_size: int
) -> Tuple[List[FileEntry], bool]:
    cd_offset, cd_count, is_zip64 = _read_eocd(mm, file_size)
    entries: List[FileEntry] = []

    mm.seek(cd_offset)
    cdh_sig = b"PK\x01\x02"

    for _ in range(cd_count):
        header = mm.read(46)
        if len(header) < 46:
            raise ValueError(
                f"Truncated central directory header: expected 46 bytes, "
                f"got {len(header)}"
            )
        if header[:4] != cdh_sig:
            raise ValueError(
                f"Invalid central directory header signature: "
                f"expected {cdh_sig!r}, got {header[:4]!r}"
            )

        compress_type = struct.unpack_from("<H", header, 10)[0]
        compressed_size32 = struct.unpack_from("<I", header, 20)[0]
        uncomp_size32 = struct.unpack_from("<I", header, 24)[0]
        fname_len = struct.unpack_from("<H", header, 28)[0]
        extra_len = struct.unpack_from("<H", header, 30)[0]
        comment_len = struct.unpack_from("<H", header, 32)[0]
        header_offset32 = struct.unpack_from("<I", header, 42)[0]

        fname_bytes = mm.read(fname_len)
        extra_bytes = mm.read(extra_len)
        mm.seek(comment_len, 1)

        filename = fname_bytes.decode("utf-8", errors="replace")

        z64 = _parse_zip64_extra(extra_bytes)

        compressed_size = z64.get("compressed_size", compressed_size32)
        uncompressed_size = z64.get("uncompressed_size", uncomp_size32)
        header_offset = z64.get("header_offset", header_offset32)

        if compressed_size32 == SENTINEL_32 and "compressed_size" not in z64:
            compressed_size = 0
        if uncomp_size32 == SENTINEL_32 and "uncompressed_size" not in z64:
            uncompressed_size = 0
        if header_offset32 == SENTINEL_32 and "header_offset" not in z64:
            header_offset = 0

        entries.append(
            FileEntry(
                filename=filename,
                header_offset=header_offset,
                compressed_size=compressed_size,
                uncompressed_size=uncompressed_size,
                compress_type=compress_type,
                cdh_extra_len=extra_len,
            )
        )

    return entries, is_zip64


LFH_FIXED = 30


def resolve_data_intervals(mm: mmap.mmap, entries: List[FileEntry]) -> None:
    lfh_sig = b"PK\x03\x04"
    file_size = mm.size()

    for e in entries:
        if e.header_offset + LFH_FIXED > file_size:
            e.data_start = e.header_offset
            e.data_end = e.header_offset + e.compressed_size
            continue

        mm.seek(e.header_offset)
        lfh = mm.read(LFH_FIXED)
        if len(lfh) < LFH_FIXED or lfh[:4] != lfh_sig:
            e.data_start = e.header_offset
            e.data_end = e.header_offset + e.compressed_size
            continue

        lfh_fname_len = struct.unpack_from("<H", lfh, 26)[0]
        lfh_extra_len = struct.unpack_from("<H", lfh, 28)[0]
        e.lfh_extra_len = lfh_extra_len

        e.data_start = e.header_offset + LFH_FIXED + lfh_fname_len + lfh_extra_len
        e.data_end = e.data_start + e.compressed_size


def check_overlapping_files(
    entries: List[FileEntry],
) -> List[Tuple[FileEntry, FileEntry]]:
    if not entries:
        return []

    sorted_e = sorted(entries, key=lambda e: e.data_start)
    overlaps: List[Tuple[FileEntry, FileEntry]] = []
    max_end = sorted_e[0].data_end
    max_end_entry = sorted_e[0]

    for e in sorted_e[1:]:
        if e.data_start < max_end:
            overlaps.append((max_end_entry, e))
        if e.data_end > max_end:
            max_end = e.data_end
            max_end_entry = e

    return overlaps


def check_extra_field_quoting(entries: List[FileEntry]) -> List[FileEntry]:
    if not entries:
        return []

    sorted_e = sorted(entries, key=lambda e: e.header_offset)
    suspicious: List[FileEntry] = []

    for i, e in enumerate(sorted_e[:-1]):
        next_e = sorted_e[i + 1]
        eff_extra = e.lfh_extra_len if e.lfh_extra_len >= 0 else e.cdh_extra_len
        if eff_extra > 0 and e.data_start >= next_e.header_offset:
            suspicious.append(e)

    return suspicious


def check_compression_ratios(
    entries: List[FileEntry], cfg: Config
) -> List[Tuple[FileEntry, float]]:
    suspicious = []
    for e in entries:
        if e.compressed_size <= 0:
            continue
        ratio = e.uncompressed_size / e.compressed_size
        limit = (
            cfg.max_bzip2_ratio
            if e.compress_type == COMPRESS_BZIP2
            else cfg.max_deflate_ratio
        )
        if ratio > limit:
            suspicious.append((e, ratio))
    return suspicious


def detect_zip_bomb(path: str, cfg: Optional[Config] = None) -> DetectionResult:
    if cfg is None:
        cfg = Config()

    zip_size = os.path.getsize(path)
    result = DetectionResult(is_bomb=False, zip_size=zip_size)

    with open(path, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        try:
            entries, is_zip64 = parse_central_directory(mm, zip_size)
        except (ValueError, struct.error) as exc:
            result.issues.append(
                Issue("parse_error", f"Could not parse central directory: {exc}")
            )
            result.is_bomb = True
            return result

        result.zip64 = is_zip64
        result.file_count = len(entries)

        try:
            resolve_data_intervals(mm, entries)
        except Exception:
            for e in entries:
                if e.data_start == 0:
                    e.data_start = e.header_offset
                    e.data_end = e.header_offset + e.compressed_size

    overlaps = check_overlapping_files(entries)
    if overlaps:
        has_full = any(a.header_offset == b.header_offset for a, b in overlaps)
        kind = "full_overlap" if has_full else "quoted_overlap"
        sample = [(a.filename, b.filename) for a, b in overlaps[:3]]
        result.issues.append(
            Issue(
                kind,
                f"Overlapping file data detected ({len(overlaps)} pair(s)). "
                f"Sample: {sample}. "
                f"Matches Fifield "
                f"{'full-overlap' if has_full else 'quoted_overlap (or giant-steps)'} "
                f"construction.",
            )
        )
        result.is_bomb = True

    extra_q = check_extra_field_quoting(entries)
    if extra_q:
        names = [e.filename for e in extra_q[:3]]
        result.issues.append(
            Issue(
                "extra_field_quoting",
                f"Extra-field quoting detected in {len(extra_q)} file(s): {names}. "
                "LFH extra fields enclose subsequent local file headers.",
            )
        )
        result.is_bomb = True

    total_uncompressed = sum(e.uncompressed_size for e in entries)
    result.total_uncompressed = total_uncompressed
    overall_ratio = total_uncompressed / zip_size if zip_size > 0 else 0.0
    result.compression_ratio = overall_ratio

    if overall_ratio > cfg.max_aggregate_ratio:
        result.issues.append(
            Issue(
                "aggregate_ratio",
                f"Extreme aggregate compression ratio: {overall_ratio:,.0f}:1 "
                f"({total_uncompressed / 1e9:.2f} GiB uncompressed from "
                f"{zip_size / 1e6:.2f} MiB zip)",
            )
        )
        result.is_bomb = True

    if total_uncompressed > cfg.max_total_uncompressed_bytes:
        result.issues.append(
            Issue(
                "total_size",
                f"Total uncompressed size {total_uncompressed / 1e9:.2f} GiB "
                f"exceeds limit of {cfg.max_total_uncompressed_bytes / 1e9:.2f} GiB",
            )
        )
        result.is_bomb = True

    bad_ratios = check_compression_ratios(entries, cfg)
    if bad_ratios:
        worst_entry, worst_ratio = max(bad_ratios, key=lambda x: x[1])
        cname = {
            COMPRESS_STORED: "stored",
            COMPRESS_DEFLATE: "DEFLATE",
            COMPRESS_BZIP2: "bzip2",
        }.get(worst_entry.compress_type, str(worst_entry.compress_type))
        limit = (
            cfg.max_bzip2_ratio
            if worst_entry.compress_type == COMPRESS_BZIP2
            else cfg.max_deflate_ratio
        )
        result.issues.append(
            Issue(
                "per_file_ratio",
                f"File '{worst_entry.filename}' ({cname}) ratio {worst_ratio:,.0f}:1 "
                f"exceeds the {cname} theoretical maximum of {limit:,.0f}:1",
            )
        )
        result.is_bomb = True

    if result.file_count > cfg.max_file_count:
        result.issues.append(
            Issue(
                "file_count",
                f"Suspiciously high file count: {result.file_count:,} "
                f"(threshold {cfg.max_file_count:,})",
            )
        )
        result.is_bomb = True

    return result


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


def _run_overlap_detection(path: str, cfg: Optional[Config]) -> None:
    """Run detect_zip_bomb against a filesystem path and raise on positive."""
    try:
        result = detect_zip_bomb(path, cfg)
    except Exception as exc:
        raise MalformedArchiveError(
            f"Failed to parse archive for overlap detection: {exc}"
        ) from exc
    if result.is_bomb:
        details = "; ".join(i.detail for i in result.issues[:2])
        raise MalformedArchiveError(f"overlapping entries detected: {details}")


def _check_overlapping_entries(
    fileobj: IO[bytes], cfg: Optional[Config] = None
) -> None:
    """Detect Fifield-style zip bombs using comprehensive detection.

    This function uses `detect_zip_bomb()` to analyse the archive for overlapping
    entries, extra-field quoting, and other Fifield 2019 attack vectors.

    For in-memory BinaryIO objects without a filesystem path, the archive is
    spilled to a temporary file to enable mmap-based detection.

    :param fileobj: A seekable binary file object.
    :param cfg: Optional Config with limits. If not provided, uses defaults.
    :raises MalformedArchiveError: If overlapping entries are detected.
    """
    path = getattr(fileobj, "name", None)

    if path is not None:
        _run_overlap_detection(path, cfg)
        return

    # BinaryIO input: spill to a temporary file so mmap-based detection
    # can run. Save and restore position so the caller's zipfile.ZipFile
    # instance is not disturbed.
    try:
        pos = fileobj.tell()
    except OSError:
        pos = None
    try:
        try:
            fileobj.seek(0)
        except OSError:
            log.warning(
                "Skipping Fifield-style zip bomb detection: "
                "in-memory archive is not seekable."
            )
            return

        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
                tmp_path = tmp.name
                tmp.write(fileobj.read())
            _run_overlap_detection(tmp_path, cfg)
        finally:
            if tmp_path is not None:
                with suppress(OSError):
                    os.unlink(tmp_path)
    finally:
        if pos is not None:
            with suppress(OSError):
                fileobj.seek(pos)


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
    if info.file_size == SENTINEL_32 or info.compress_size == SENTINEL_32:
        zip64 = _parse_zip64_extra(info.extra) if info.extra else {}
        if not zip64:
            raise MalformedArchiveError(
                f"Entry {info.filename!r} has a ZIP64 sentinel (0xFFFFFFFF) "
                f"in the 32-bit size field but no ZIP64 extra field is present. "
                f"Archive is malformed."
            )
        return

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
    max_total_size: int,
) -> None:
    """Phase A: run all pre-extraction static checks.

    :param zf: An open zipfile.ZipFile instance (read-only access).
    :param max_files: Maximum number of entries permitted.
    :param max_file_size: Maximum permitted uncompressed size for any entry.
    :param max_total_size: Maximum permitted total uncompressed size.
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
        cfg = Config(
            max_total_uncompressed_bytes=max_total_size,
            max_file_count=max_files,
        )
        _check_overlapping_entries(zf.fp, cfg)

    for info in entries:
        _validate_entry(info, max_file_size)
