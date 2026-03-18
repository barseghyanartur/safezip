"""Tests for Phase C: streaming extraction (the Streamer)."""

import io
import zipfile

import pytest

from safezip import (
    CompressionRatioError,
    FileSizeExceededError,
    MalformedArchiveError,
    SafeZipFile,
)

__author__ = "Artur Barseghyan <artur.barseghyan@gmail.com>"
__copyright__ = "2026 Artur Barseghyan"
__license__ = "MIT"


class TestFileSizeLimit:
    """Streamer enforces per-member file size limits at stream time."""

    def test_size_exceeded_raises(self, tmp_path):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
            zf.writestr("data.bin", b"A" * 1000)
        p = tmp_path / "large.zip"
        p.write_bytes(buf.getvalue())
        dest = tmp_path / "out"
        dest.mkdir()

        with (
            pytest.raises(FileSizeExceededError),
            SafeZipFile(p, max_file_size=500) as zf,
        ):
            zf.extractall(dest)

    def test_no_partial_file_after_size_failure(self, tmp_path):
        """Atomic write: no partial file must remain after FileSizeExceededError."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
            zf.writestr("data.bin", b"A" * 1000)
        p = tmp_path / "large.zip"
        p.write_bytes(buf.getvalue())
        dest = tmp_path / "out"
        dest.mkdir()

        with (
            pytest.raises(FileSizeExceededError),
            SafeZipFile(p, max_file_size=500) as zf,
        ):
            zf.extractall(dest)

        # No partial files or temp files should remain
        remaining = list(dest.rglob("*"))
        assert not remaining, f"Partial files found: {remaining}"

    def test_size_at_limit_passes(self, tmp_path):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
            zf.writestr("data.bin", b"A" * 100)
        p = tmp_path / "ok.zip"
        p.write_bytes(buf.getvalue())
        dest = tmp_path / "out"
        dest.mkdir()

        with SafeZipFile(p, max_file_size=100) as zf:
            zf.extractall(dest)
        assert (dest / "data.bin").read_bytes() == b"A" * 100


class TestTotalSizeLimit:
    """Streamer enforces cumulative total size across all members."""

    def test_total_size_exceeded(self, tmp_path):
        """Total size limit enforced during Guard phase when limits are threaded."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
            for i in range(5):
                zf.writestr(f"file_{i}.bin", b"A" * 300)
        p = tmp_path / "multi.zip"
        p.write_bytes(buf.getvalue())
        dest = tmp_path / "out"
        dest.mkdir()

        with pytest.raises(MalformedArchiveError):
            SafeZipFile(p, max_file_size=1000, max_total_size=1000)


class TestCompressionRatioLimit:
    """Streamer enforces per-member and total compression ratio limits."""

    def test_per_member_ratio_exceeded(self, high_ratio_archive, tmp_path):
        """High-ratio archive (zeros) triggers per-member ratio check."""
        dest = tmp_path / "out"
        dest.mkdir()
        with (
            pytest.raises(CompressionRatioError),
            SafeZipFile(high_ratio_archive, max_per_member_ratio=10.0) as zf,
        ):
            zf.extractall(dest)

    def test_no_partial_file_after_ratio_failure(self, high_ratio_archive, tmp_path):
        """Atomic write: no partial file must remain after CompressionRatioError."""
        dest = tmp_path / "out"
        dest.mkdir()

        with (
            pytest.raises(CompressionRatioError),
            SafeZipFile(high_ratio_archive, max_per_member_ratio=10.0) as zf,
        ):
            zf.extractall(dest)

        remaining = [f for f in dest.rglob("*") if not f.is_dir()]
        assert not remaining, f"Partial files found: {remaining}"

    def test_high_ratio_passes_with_generous_limit(self, high_ratio_archive, tmp_path):
        """Same archive passes if we allow a high ratio (both per-member and total)."""
        dest = tmp_path / "out"
        dest.mkdir()
        with SafeZipFile(
            high_ratio_archive,
            max_per_member_ratio=2000.0,
            max_total_ratio=2000.0,
            max_file_size=5 * 1024 * 1024,
        ) as zf:
            zf.extractall(dest)
        assert (dest / "zeros.bin").exists()


class TestAtomicWrite:
    """Extraction destinations are created atomically."""

    def test_successful_extraction_creates_file(self, tmp_path):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("output.txt", b"hello safezip")
        p = tmp_path / "ok.zip"
        p.write_bytes(buf.getvalue())
        dest = tmp_path / "out"
        dest.mkdir()

        with SafeZipFile(p) as zf:
            zf.extractall(dest)
        assert (dest / "output.txt").read_bytes() == b"hello safezip"

    def test_extract_single_member(self, tmp_path):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("a.txt", b"AAA")
            zf.writestr("b.txt", b"BBB")
        p = tmp_path / "two.zip"
        p.write_bytes(buf.getvalue())
        dest = tmp_path / "out"
        dest.mkdir()

        with SafeZipFile(p) as zf:
            zf.extract("a.txt", dest)
        assert (dest / "a.txt").read_bytes() == b"AAA"
        assert not (dest / "b.txt").exists()

    def test_no_temp_files_after_success(self, tmp_path):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("hello.txt", b"world")
        p = tmp_path / "ok.zip"
        p.write_bytes(buf.getvalue())
        dest = tmp_path / "out"
        dest.mkdir()

        with SafeZipFile(p) as zf:
            zf.extractall(dest)

        all_files = list(dest.rglob("*"))
        temp_files = [f for f in all_files if ".safezip_tmp_" in f.name]
        assert not temp_files
