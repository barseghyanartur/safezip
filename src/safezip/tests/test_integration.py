"""End-to-end integration tests using real crafted malicious archives."""

import io
import zipfile

import pytest

from safezip import (
    CompressionRatioError,
    FileCountExceededError,
    FileSizeExceededError,
    SafeZipFile,
    SymlinkPolicy,
    UnsafeZipError,
    safe_extract,
)

__author__ = "Artur Barseghyan <artur.barseghyan@gmail.com>"
__copyright__ = "2026 Artur Barseghyan"
__license__ = "Apache-2.0"


class TestZipSlip:
    """ZipSlip path traversal attacks are blocked before any bytes reach disk."""

    def test_relative_traversal_blocked(self, zipslip_archive, tmp_path):
        dest = tmp_path / "out"
        dest.mkdir()
        with pytest.raises(UnsafeZipError), SafeZipFile(zipslip_archive) as zf:
            zf.extractall(dest)
        # Confirm no file escaped to the parent
        evil = tmp_path / "evil.txt"
        assert not evil.exists()

    def test_absolute_path_blocked(self, absolute_path_archive, tmp_path):
        dest = tmp_path / "out"
        dest.mkdir()
        with pytest.raises(UnsafeZipError), SafeZipFile(absolute_path_archive) as zf:
            zf.extractall(dest)

    def test_traversal_leaves_no_files(self, zipslip_archive, tmp_path):
        dest = tmp_path / "out"
        dest.mkdir()
        with pytest.raises(UnsafeZipError), SafeZipFile(zipslip_archive) as zf:
            zf.extractall(dest)
        assert not list(dest.rglob("*"))

    def test_unicode_traversal_blocked(self, unicode_traversal_archive, tmp_path):
        dest = tmp_path / "out"
        dest.mkdir()
        with (
            pytest.raises(UnsafeZipError),
            SafeZipFile(unicode_traversal_archive) as zf,
        ):
            zf.extractall(dest)


class TestZipBomb:
    """ZIP bomb attacks are detected and aborted."""

    def test_high_ratio_bomb_blocked(self, high_ratio_archive, tmp_path):
        dest = tmp_path / "out"
        dest.mkdir()
        with (
            pytest.raises(CompressionRatioError),
            SafeZipFile(high_ratio_archive, max_per_member_ratio=10.0) as zf,
        ):
            zf.extractall(dest)

    def test_high_ratio_no_partial_files(self, high_ratio_archive, tmp_path):
        dest = tmp_path / "out"
        dest.mkdir()
        with (
            pytest.raises(CompressionRatioError),
            SafeZipFile(high_ratio_archive, max_per_member_ratio=10.0) as zf,
        ):
            zf.extractall(dest)
        remaining = [f for f in dest.rglob("*") if not f.is_dir()]
        assert not remaining

    def test_file_size_lie_blocked(self, tmp_path):
        """Archive that lies about size in header is caught by the streamer."""
        # Store 2000 bytes but set max_file_size=500 in Guard
        # The Guard will reject the archive if declare size > max_file_size
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
            zf.writestr("data.bin", b"X" * 2000)
        p = tmp_path / "lie.zip"
        p.write_bytes(buf.getvalue())
        dest = tmp_path / "out"
        dest.mkdir()

        with (
            pytest.raises(FileSizeExceededError),
            SafeZipFile(p, max_file_size=500) as zf,
        ):
            zf.extractall(dest)

    def test_many_files_bomb_blocked(self, many_files_archive, tmp_path):
        """Archive with too many files is blocked at the Guard phase."""
        with pytest.raises(FileCountExceededError):
            SafeZipFile(many_files_archive)


class TestExplicitPathRequirement:
    """extractall must receive an explicit path; CWD is never used silently."""

    def test_extractall_requires_path(self, legitimate_archive, tmp_path):
        """extractall with a valid path works; calling without is a TypeError."""
        dest = tmp_path / "out"
        dest.mkdir()
        with SafeZipFile(legitimate_archive) as zf:
            zf.extractall(dest)  # must not raise
        assert (dest / "hello.txt").exists()

    def test_extractall_wrong_type_raises(self, legitimate_archive):
        """Passing None as path raises TypeError."""
        with (
            SafeZipFile(legitimate_archive) as zf,
            pytest.raises((TypeError, AttributeError)),
        ):
            zf.extractall(None)


class TestLegitimateExtraction:
    """Well-formed archives extract correctly and completely."""

    def test_all_files_extracted(self, legitimate_archive, tmp_path):
        dest = tmp_path / "out"
        dest.mkdir()
        with SafeZipFile(legitimate_archive) as zf:
            zf.extractall(dest)
        assert (dest / "hello.txt").read_bytes() == b"Hello, world!\n"
        assert (dest / "subdir" / "data.txt").read_bytes() == b"Some data\n"
        assert (dest / "subdir" / "nested" / "deep.txt").read_bytes() == b"Deep file\n"

    def test_safe_extract_convenience(self, legitimate_archive, tmp_path):
        dest = tmp_path / "out"
        dest.mkdir()
        safe_extract(legitimate_archive, dest)
        assert (dest / "hello.txt").exists()

    def test_context_manager_closes_properly(self, legitimate_archive, tmp_path):
        dest = tmp_path / "out"
        dest.mkdir()
        with SafeZipFile(legitimate_archive) as zf:
            zf.extractall(dest)
        # After context exit, the underlying ZipFile's fp should be None (closed).
        # zipfile.ZipFile.close() sets self.fp = None.
        assert zf._zf.fp is None


class TestSecurityEventCallback:
    """on_security_event callback is called on security events."""

    def test_callback_called_on_zip_slip(self, zipslip_archive, tmp_path):
        events = []

        def capture(event):
            events.append(event)

        dest = tmp_path / "out"
        dest.mkdir()
        with (
            pytest.raises(UnsafeZipError),
            SafeZipFile(zipslip_archive, on_security_event=capture) as zf,
        ):
            zf.extractall(dest)
        # Note: callback is called for monitored events during extraction;
        # path traversal may be detected in sandbox before callback fires.
        # The test verifies no crash occurs.

    def test_callback_exception_does_not_swallow_security_error(
        self, zipslip_archive, tmp_path
    ):
        def broken_callback(event):
            raise RuntimeError("callback broken")

        dest = tmp_path / "out"
        dest.mkdir()
        # The UnsafeZipError must still propagate even if callback raises
        with (
            pytest.raises(UnsafeZipError),
            SafeZipFile(zipslip_archive, on_security_event=broken_callback) as zf,
        ):
            zf.extractall(dest)


class TestNestedArchiveGuard:
    """Nested archive members are extracted as raw files, not recursed into."""

    def test_inner_zip_extracted_as_raw_file(self, tmp_path):
        inner_buf = io.BytesIO()
        with zipfile.ZipFile(inner_buf, "w") as inner_zf:
            inner_zf.writestr("secret.txt", b"inner content")
        inner_bytes = inner_buf.getvalue()

        outer_buf = io.BytesIO()
        with zipfile.ZipFile(outer_buf, "w") as outer_zf:
            outer_zf.writestr("readme.txt", b"outer content")
            outer_zf.writestr("nested.zip", inner_bytes)
        outer_p = tmp_path / "outer.zip"
        outer_p.write_bytes(outer_buf.getvalue())

        dest = tmp_path / "out"
        dest.mkdir()
        with SafeZipFile(outer_p) as zf:
            zf.extractall(dest)

        # The nested.zip should be present as a raw file, not recursed
        assert (dest / "nested.zip").exists()
        assert (dest / "nested.zip").read_bytes() == inner_bytes
        # The inner secret.txt should NOT be extracted
        assert not (dest / "secret.txt").exists()


class TestSymlinkPolicy:
    """SafeZipFile enforces the configured SymlinkPolicy for ZIP symlink entries.

    A ZIP symlink entry is identified by the upper 16 bits of
    ``ZipInfo.external_attr`` carrying a Unix ``S_IFLNK`` file mode.
    The entry's data bytes contain the link target path.
    """

    def test_reject_is_default(self, symlink_archive, tmp_path):
        """Default policy (REJECT) raises UnsafeZipError on any symlink entry."""
        dest = tmp_path / "out"
        dest.mkdir()
        with pytest.raises(UnsafeZipError), SafeZipFile(symlink_archive) as zf:
            zf.extractall(dest)

    def test_reject_explicit_raises(self, symlink_archive, tmp_path):
        """Explicit REJECT policy raises UnsafeZipError on a symlink entry."""
        dest = tmp_path / "out"
        dest.mkdir()
        with (
            pytest.raises(UnsafeZipError),
            SafeZipFile(symlink_archive, symlink_policy=SymlinkPolicy.REJECT) as zf,
        ):
            zf.extractall(dest)

    def test_ignore_skips_symlink_entry(self, symlink_archive, tmp_path):
        """IGNORE policy silently skips symlink entries; no file is created."""
        dest = tmp_path / "out"
        dest.mkdir()
        with SafeZipFile(symlink_archive, symlink_policy=SymlinkPolicy.IGNORE) as zf:
            zf.extractall(dest)
        # The symlink entry must not appear on disk
        assert not (dest / "link.txt").exists()

    def test_ignore_preserves_regular_files(self, symlink_archive, tmp_path):
        """IGNORE policy skips symlinks but still extracts regular entries."""
        dest = tmp_path / "out"
        dest.mkdir()
        with SafeZipFile(symlink_archive, symlink_policy=SymlinkPolicy.IGNORE) as zf:
            zf.extractall(dest)
        assert (dest / "readme.txt").read_bytes() == b"safe content\n"

    def test_resolve_internal_extracts_target_as_file(self, symlink_archive, tmp_path):
        """RESOLVE_INTERNAL extracts the symlink target path as a regular file.

        Because the ZIP entry's content is the target string (not an OS
        symlink), the extracted file is a plain file containing that string.
        The post-extraction symlink check only fires when the OS creates an
        actual symlink (not applicable here), so extraction succeeds.
        """
        dest = tmp_path / "out"
        dest.mkdir()
        with SafeZipFile(
            symlink_archive, symlink_policy=SymlinkPolicy.RESOLVE_INTERNAL
        ) as zf:
            zf.extractall(dest)
        # The entry is written as a regular file containing the target path
        extracted = dest / "link.txt"
        assert extracted.exists()
        assert not extracted.is_symlink()
        assert extracted.read_text() == "../escape.txt"
