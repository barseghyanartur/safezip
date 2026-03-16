"""Tests for Phase A: the Guard (pre-extraction validation)."""

import io
import struct
import zipfile
import zlib

import pytest

from safezip import (
    FileCountExceededError,
    FileSizeExceededError,
    MalformedArchiveError,
    SafeZipFile,
)
from safezip._guard import ScanResult, ZipInspector

__author__ = "Artur Barseghyan <artur.barseghyan@gmail.com>"
__copyright__ = "2026 Artur Barseghyan"
__license__ = "MIT"


class TestFileCountLimit:
    """Guard rejects archives with too many entries."""

    def test_many_files_raises(self, many_files_archive, tmp_path):
        with pytest.raises(FileCountExceededError):
            SafeZipFile(many_files_archive)

    def test_many_files_custom_limit_passes(self, many_files_archive, tmp_path):
        # Allow up to 20 000 files - should open without error
        with SafeZipFile(many_files_archive, max_files=20_000):
            pass

    def test_file_count_exactly_at_limit(self, tmp_path):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            for i in range(5):
                zf.writestr(f"file_{i}.txt", b"x")
        p = tmp_path / "five.zip"
        p.write_bytes(buf.getvalue())
        with SafeZipFile(p, max_files=5):
            pass

    def test_file_count_one_over_limit(self, tmp_path):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            for i in range(6):
                zf.writestr(f"file_{i}.txt", b"x")
        p = tmp_path / "six.zip"
        p.write_bytes(buf.getvalue())
        with pytest.raises(FileCountExceededError):
            SafeZipFile(p, max_files=5)


class TestDeclaredFileSizeLimit:
    """Guard rejects archives whose declared sizes exceed max_file_size."""

    def test_large_declared_size_raises(self, tmp_path):
        # Declare a very large file but store tiny content
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            info = zipfile.ZipInfo("big.bin")
            zf.writestr(info, b"tiny")

        # Manually patch the ZipInfo to report a huge size - instead,
        # test via the limit: store a 200-byte file and set limit=100
        buf2 = io.BytesIO()
        with zipfile.ZipFile(buf2, "w") as zf2:
            zf2.writestr("data.bin", b"A" * 200)
        p = tmp_path / "large.zip"
        p.write_bytes(buf2.getvalue())

        with pytest.raises(FileSizeExceededError):
            SafeZipFile(p, max_file_size=100)

    def test_size_exactly_at_limit_passes(self, tmp_path):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("data.bin", b"A" * 100)
        p = tmp_path / "exact.zip"
        p.write_bytes(buf.getvalue())
        with SafeZipFile(p, max_file_size=100):
            pass


class TestNullByteInFilename:
    """Null bytes in ZIP filenames are neutralised by Python's zipfile layer.

    Python 3.x's :mod:`zipfile` truncates filenames at the first null byte
    when reading the central directory (e.g. ``safe\x00../../etc/passwd``
    becomes ``safe``).  Our Guard therefore never sees a null byte in
    ``ZipInfo.filename``; the Sandbox's ``resolve_member_path`` carries the
    defence-in-depth check for callers that bypass ``zipfile``.

    This test verifies the safe outcome: no traversal path survives Python's
    null-byte truncation.
    """

    def test_null_byte_filename_truncated_safely(self, null_byte_filename_archive):
        """Python strips null bytes; the traversal portion is never evaluated."""
        # Python truncates 'safe\x00../../etc/passwd' → 'safe'
        with SafeZipFile(null_byte_filename_archive) as zf:
            names = zf.namelist()
        # No null bytes survive Python's filename decoding
        assert not any("\x00" in n for n in names), (
            f"Null byte survived Python's filename decoding: {names!r}"
        )
        # No directory-traversal components should be present
        assert not any(".." in n for n in names), (
            f"Traversal component present after null-byte truncation: {names!r}"
        )


class TestZip64Inconsistency:
    """Guard detects ZIP64 extra fields that disagree with central directory."""

    def test_zip64_inconsistency_raises(self, zip64_inconsistency_archive):
        with pytest.raises(MalformedArchiveError):
            SafeZipFile(zip64_inconsistency_archive)


class TestLegitimateArchive:
    """Guard passes well-formed archives."""

    def test_legitimate_archive_passes(self, legitimate_archive):
        with SafeZipFile(legitimate_archive) as zf:
            assert len(zf.namelist()) == 3

    def test_namelist_accessible(self, legitimate_archive):
        with SafeZipFile(legitimate_archive) as zf:
            names = zf.namelist()
        assert "hello.txt" in names

    def test_infolist_accessible(self, legitimate_archive):
        with SafeZipFile(legitimate_archive) as zf:
            infos = zf.infolist()
        assert any(i.filename == "hello.txt" for i in infos)

    def test_getinfo_accessible(self, legitimate_archive):
        with SafeZipFile(legitimate_archive) as zf:
            info = zf.getinfo("hello.txt")
        assert info.filename == "hello.txt"


class TestOverlappingEntryDetection:
    """Guard rejects archives with overlapping local entries (Fifield-style bombs)."""

    def test_fifield_bomb_raises_malformed(self, fifield_bomb_archive):
        with pytest.raises(MalformedArchiveError, match="overlapping"):
            SafeZipFile(fifield_bomb_archive)

    def test_fifield_bomb_no_extraction_attempted(self, fifield_bomb_archive, tmp_path):
        dest = tmp_path / "out"
        dest.mkdir()
        with pytest.raises(MalformedArchiveError):
            SafeZipFile(fifield_bomb_archive)
        assert list(dest.iterdir()) == []

    def test_legitimate_archive_passes_overlap_check(self, legitimate_archive):
        with SafeZipFile(legitimate_archive) as zf:
            assert len(zf.namelist()) > 0

    def test_overlap_check_does_not_decompress(self, fifield_bomb_archive, tmp_path):
        with pytest.raises(MalformedArchiveError, match="overlapping"):
            SafeZipFile(fifield_bomb_archive, max_per_member_ratio=100_000.0)


def _lfh(filename: bytes, data: bytes, compress_type: int = 0) -> bytes:
    """Build a Local File Header + data."""
    return (
        struct.pack(
            "<LHHHHHLLLHH",
            0x04034B50,
            20,
            0,
            compress_type,
            0,
            0,
            zlib.crc32(data) & 0xFFFFFFFF,
            len(data),
            len(data),
            len(filename),
            0,
        )
        + filename
        + data
    )


def _cdh(
    filename: bytes, data: bytes, local_offset: int, compress_type: int = 0
) -> bytes:
    """Build a Central Directory Header."""
    return (
        struct.pack(
            "<LHHHHHHLLLHHHHHLL",
            0x02014B50,
            20,
            20,
            0,
            compress_type,
            0,
            0,
            zlib.crc32(data) & 0xFFFFFFFF,
            len(data),
            len(data),
            len(filename),
            0,
            0,
            0,
            0,
            0,
            local_offset,
        )
        + filename
    )


def _eocd(
    num_entries: int, cd_size: int, cd_offset: int, comment: bytes = b""
) -> bytes:
    """Build an End of Central Directory record."""
    return (
        struct.pack(
            "<LHHHHLLH",
            0x06054B50,
            0,
            0,
            num_entries,
            num_entries,
            cd_size,
            cd_offset,
            len(comment),
        )
        + comment
    )


def _build_zip(*files: tuple[bytes, bytes]) -> bytes:
    """Build a well-formed zip from (filename, data) pairs."""
    lfhs, cdhs = [], []
    cursor = 0
    for fname, data in files:
        lfh = _lfh(fname, data)
        cdhs.append(_cdh(fname, data, cursor))
        lfhs.append(lfh)
        cursor += len(lfh)

    cd = b"".join(cdhs)
    return b"".join(lfhs) + cd + _eocd(len(files), len(cd), cursor)


def _build_overlap_zip(fname_a: bytes, fname_b: bytes, data: bytes) -> bytes:
    """Build a zip where two CDH entries point to the same LFH offset."""
    lfh = _lfh(fname_a, data)
    cdh1 = _cdh(fname_a, data, 0)
    cdh2 = _cdh(fname_b, data, 0)
    cd = cdh1 + cdh2
    return lfh + cd + _eocd(2, len(cd), len(lfh))


class TestZipInspector:
    """Tests for the ZipInspector overlap detection."""

    def _scan(self, data: bytes) -> ScanResult:
        return ZipInspector(io.BytesIO(data)).scan()

    def test_clean_single_file(self):
        data = _build_zip((b"readme.txt", b"hello"))
        result = self._scan(data)
        assert result.is_bomb is False

    def test_clean_two_files_sequential(self):
        data = _build_zip(
            (b"a.txt", b"first file contents"),
            (b"b.txt", b"second file contents"),
        )
        assert self._scan(data).is_bomb is False

    def test_clean_many_files(self):
        files = [(f"file{i}.txt".encode(), f"content {i}".encode()) for i in range(50)]
        data = _build_zip(*files)
        assert self._scan(data).is_bomb is False

    def test_clean_empty_file_entry(self):
        data = _build_zip((b"empty", b""))
        assert self._scan(data).is_bomb is False

    def test_overlap_two_cdh_same_offset(self):
        data = _build_overlap_zip(b"a", b"b", b"kernel data")
        assert self._scan(data).is_bomb is True

    def test_overlap_detail_is_populated(self):
        data = _build_overlap_zip(b"x", b"y", b"data")
        result = self._scan(data)
        assert result.is_bomb is True
        assert result.overlap_detail is not None

    def test_invalid_not_a_zip(self):
        result = self._scan(b"this is not a zip file at all")
        assert result.is_bomb is None

    def test_invalid_empty_bytes(self):
        result = self._scan(b"")
        assert result.is_bomb is None

    def test_invalid_truncated_eocd(self):
        result = self._scan(b"PK\x05\x06\x00\x00")
        assert result.is_bomb is None

    def test_invalid_garbage_with_pk_bytes(self):
        result = self._scan(b"\x00" * 100 + b"PK\x05\x06" + b"\xff" * 18)
        assert result.is_bomb is None

    def test_invalid_cdh_signature_mismatch(self):
        raw = bytearray(_build_zip((b"f", b"data")))
        cdh_pos = raw.find(b"PK\x01\x02")
        raw[cdh_pos] = 0xFF
        assert self._scan(bytes(raw)).is_bomb is None

    def test_invalid_lfh_signature_mismatch(self):
        raw = bytearray(_build_zip((b"f", b"data")))
        raw[0] = 0xFF
        assert self._scan(bytes(raw)).is_bomb is None

    def test_gap_does_not_trigger_bomb(self):
        gap = b"\x00" * 16
        lfh1 = _lfh(b"a", b"data1")
        lfh2 = _lfh(b"b", b"data2")
        off1 = 0
        off2 = len(lfh1) + len(gap)
        cdh1 = _cdh(b"a", b"data1", off1)
        cdh2 = _cdh(b"b", b"data2", off2)
        cd = cdh1 + cdh2
        raw = lfh1 + gap + lfh2 + cd + _eocd(2, len(cd), off2 + len(lfh2))
        assert self._scan(raw).is_bomb is False

    def test_leading_bytes_not_a_bomb(self):
        prefix = b"\x00" * 32
        lfh = _lfh(b"x", b"payload")
        cdh = _cdh(b"x", b"payload", len(prefix))
        cd = cdh
        raw = prefix + lfh + cd + _eocd(1, len(cd), len(prefix) + len(lfh))
        assert self._scan(raw).is_bomb is False
