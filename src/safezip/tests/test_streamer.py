"""Tests for Phase C: streaming extraction (the Streamer)."""

import io
import os
import stat
import zipfile

import pytest

from safezip import (
    CompressionRatioError,
    FileSizeExceededError,
    MalformedArchiveError,
    SafeZipFile,
    _streamer,
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


def _plant_at_staging_path(monkeypatch, plant):
    """Simulate a local attacker who wins the race for the staging name.

    Only ``safezip._streamer._staging_path`` is replaced. The replacement
    calls *plant* to create an entry at a fixed name next to the destination,
    then returns that path, as if the attacker had created it first.
    """

    def fake_staging_path(dest):
        path = dest.parent / f"{dest.name}.safezip_tmp_planted"
        plant(path)
        return path

    monkeypatch.setattr(_streamer, "_staging_path", fake_staging_path)


class TestStagingFileCreation:
    """The staging file is created exclusively and never follows a symlink."""

    def _archive(self, tmp_path):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("x.txt", b"ATTACKER")
        p = tmp_path / "x.zip"
        p.write_bytes(buf.getvalue())
        return p

    def test_planted_symlink_is_not_followed(self, tmp_path, monkeypatch):
        archive = self._archive(tmp_path)
        victim = tmp_path / "victim.txt"
        victim.write_bytes(b"ORIGINAL")
        dest = tmp_path / "out"
        dest.mkdir()
        _plant_at_staging_path(monkeypatch, lambda p: os.symlink(victim, p))

        with pytest.raises(FileExistsError), SafeZipFile(archive) as zf:
            zf.extractall(dest)

        assert victim.read_bytes() == b"ORIGINAL"
        assert not (dest / "x.txt").exists()

    def test_planted_dangling_symlink_creates_nothing(self, tmp_path, monkeypatch):
        """O_CREAT alone would create the link's target; O_EXCL must not."""
        archive = self._archive(tmp_path)
        target = tmp_path / "created_by_extractor.txt"
        dest = tmp_path / "out"
        dest.mkdir()
        _plant_at_staging_path(monkeypatch, lambda p: os.symlink(target, p))

        with pytest.raises(FileExistsError), SafeZipFile(archive) as zf:
            zf.extractall(dest)

        assert not target.exists()
        assert not (dest / "x.txt").exists()

    def test_planted_regular_file_is_not_overwritten(self, tmp_path, monkeypatch):
        archive = self._archive(tmp_path)
        dest = tmp_path / "out"
        dest.mkdir()
        _plant_at_staging_path(monkeypatch, lambda p: p.write_bytes(b"PLANTED"))

        with pytest.raises(FileExistsError), SafeZipFile(archive) as zf:
            zf.extractall(dest)

        planted = dest / "x.txt.safezip_tmp_planted"
        assert planted.read_bytes() == b"PLANTED"
        assert not (dest / "x.txt").exists()

    def test_planted_symlink_is_left_in_place(self, tmp_path, monkeypatch):
        """Cleanup only ever removes a staging file safezip created itself."""
        archive = self._archive(tmp_path)
        victim = tmp_path / "victim.txt"
        victim.write_bytes(b"ORIGINAL")
        dest = tmp_path / "out"
        dest.mkdir()
        _plant_at_staging_path(monkeypatch, lambda p: os.symlink(victim, p))

        with pytest.raises(FileExistsError), SafeZipFile(archive) as zf:
            zf.extractall(dest)

        assert (dest / "x.txt.safezip_tmp_planted").is_symlink()

    def test_extracted_file_mode_unchanged(self, tmp_path):
        """Exclusive creation keeps the mode a plain ``open(..., "wb")`` gives."""
        archive = self._archive(tmp_path)
        dest = tmp_path / "out"
        dest.mkdir()
        reference = tmp_path / "reference"
        with open(reference, "wb"):
            pass

        with SafeZipFile(archive) as zf:
            zf.extractall(dest)

        extracted = dest / "x.txt"
        assert extracted.read_bytes() == b"ATTACKER"
        assert stat.S_IMODE(extracted.stat().st_mode) == stat.S_IMODE(
            reference.stat().st_mode
        )
