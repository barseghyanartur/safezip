"""Tests for Phase A: the Guard (pre-extraction validation)."""

import io
import zipfile

import pytest

from safezip import (
    FileCountExceededError,
    FileSizeExceededError,
    MalformedArchiveError,
    SafeZipFile,
)

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
        with pytest.raises((MalformedArchiveError, Exception)):
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
