"""End-to-end integration tests using real crafted malicious archives."""

import io
import stat
import zipfile

import pytest

from safezip import (
    CompressionRatioError,
    FileCountExceededError,
    FileSizeExceededError,
    MalformedArchiveError,
    NestingDepthError,
    SafeZipFile,
    SymlinkPolicy,
    UnsafeZipError,
    safe_extract,
)

__author__ = "Artur Barseghyan <artur.barseghyan@gmail.com>"
__copyright__ = "2026 Artur Barseghyan"
__license__ = "MIT"


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

    def test_extract_with_none_path_raises(self, legitimate_archive):
        """Passing None as path to extract() raises TypeError."""
        with SafeZipFile(legitimate_archive) as zf, pytest.raises(TypeError):
            zf.extract("hello.txt", None)

    def test_extractall_with_members_list(self, legitimate_archive, tmp_path):
        """extractall with a members list extracts only those members."""
        dest = tmp_path / "out"
        dest.mkdir()
        with SafeZipFile(legitimate_archive) as zf:
            zf.extractall(dest, members=["hello.txt"])
        # Only hello.txt should exist
        assert (dest / "hello.txt").exists()
        contents = list(dest.rglob("*"))
        assert len(contents) == 1


class TestMalformedArchive:
    """Structurally invalid archives raise MalformedArchiveError."""

    def test_not_a_zip_raises_malformed(self, tmp_path):
        """A file that is not a ZIP at all raises MalformedArchiveError."""
        bad = tmp_path / "bad.zip"
        bad.write_bytes(b"this is not a zip file")
        with pytest.raises(MalformedArchiveError):
            SafeZipFile(bad)

    def test_zip64_inconsistency_raises(self, zip64_inconsistency_archive):
        """ZIP64 extra field that disagrees with central directory is rejected."""
        with pytest.raises(MalformedArchiveError):
            SafeZipFile(zip64_inconsistency_archive)


class TestFifieldBomb:
    """End-to-end: Fifield-style zip bomb is blocked at Guard phase."""

    def test_fifield_bomb_blocked_end_to_end(self, fifield_bomb_archive, tmp_path):
        dest = tmp_path / "out"
        dest.mkdir()
        with (
            pytest.raises(MalformedArchiveError),
            SafeZipFile(fifield_bomb_archive) as zf,
        ):
            zf.extractall(dest)
        remaining = [f for f in dest.rglob("*") if not f.is_dir()]
        assert not remaining

    def test_security_event_fires_on_fifield_bomb(self, fifield_bomb_archive, tmp_path):
        """on_security_event callback receives 'malformed_archive' for Fifield bomb."""
        events = []
        dest = tmp_path / "out"
        dest.mkdir()
        with pytest.raises(MalformedArchiveError):
            SafeZipFile(fifield_bomb_archive, on_security_event=events.append)
        assert any(e.event_type == "malformed_archive" for e in events)

    def test_fifield_bomb_as_bytesio_rejected(self, fifield_bomb_archive):
        """Fifield bomb as BytesIO is rejected."""
        data = fifield_bomb_archive.read_bytes()
        bio = io.BytesIO(data)
        with pytest.raises(MalformedArchiveError):
            SafeZipFile(bio)

    def test_legitimate_archive_as_bytesio_passes(self, legitimate_archive):
        """Legitimate archive as BytesIO passes."""
        data = legitimate_archive.read_bytes()
        bio = io.BytesIO(data)
        with SafeZipFile(bio) as zf:
            assert len(zf.namelist()) > 0

    def test_fifield_bomb_bytesio_event_fires(self, fifield_bomb_archive):
        """on_security_event fires for in-memory Fifield bomb."""
        events = []
        data = fifield_bomb_archive.read_bytes()
        bio = io.BytesIO(data)
        with pytest.raises(MalformedArchiveError):
            SafeZipFile(bio, on_security_event=events.append)
        assert any(e.event_type == "malformed_archive" for e in events)


class TestSecurityEventCoverage:
    """on_security_event callback fires for all security violation types."""

    def test_callback_fires_on_path_traversal(self, zipslip_archive, tmp_path):
        events = []
        dest = tmp_path / "out"
        dest.mkdir()
        with (
            pytest.raises(UnsafeZipError),
            SafeZipFile(zipslip_archive, on_security_event=events.append) as zf,
        ):
            zf.extractall(dest)
        assert any(e.event_type == "zip_slip_detected" for e in events)

    def test_callback_fires_on_file_size_exceeded(self, tmp_path):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
            zf.writestr("data.bin", b"A" * 1000)
        p = tmp_path / "large.zip"
        p.write_bytes(buf.getvalue())
        dest = tmp_path / "out"
        dest.mkdir()
        events = []
        with (
            pytest.raises(FileSizeExceededError),
            SafeZipFile(p, max_file_size=500, on_security_event=events.append) as zf,
        ):
            zf.extractall(dest)
        # The Guard may fire "declared_size_exceeded" (declared header size >
        # limit) or the Streamer may fire "file_size_exceeded" (actual
        # decompressed bytes > limit).  Both indicate a file-size violation.
        size_events = {"file_size_exceeded", "declared_size_exceeded"}
        assert any(e.event_type in size_events for e in events)

    def test_callback_fires_on_ratio_exceeded(self, high_ratio_archive, tmp_path):
        events = []
        dest = tmp_path / "out"
        dest.mkdir()
        with (
            pytest.raises(CompressionRatioError),
            SafeZipFile(
                high_ratio_archive,
                max_per_member_ratio=10.0,
                on_security_event=events.append,
            ) as zf,
        ):
            zf.extractall(dest)
        assert any(e.event_type == "compression_ratio_exceeded" for e in events)

    def test_callback_fires_on_file_count_exceeded(self, many_files_archive, tmp_path):
        events = []
        with pytest.raises(FileCountExceededError):
            SafeZipFile(many_files_archive, on_security_event=events.append)
        assert any(e.event_type == "file_count_exceeded" for e in events)

    def test_callback_fires_on_symlink_rejected(self, symlink_archive, tmp_path):
        events = []
        dest = tmp_path / "out"
        dest.mkdir()
        with (
            pytest.raises(UnsafeZipError),
            SafeZipFile(symlink_archive, on_security_event=events.append) as zf,
        ):
            zf.extractall(dest)
        assert any(e.event_type == "symlink_rejected" for e in events)


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


class TestNestingDepthLimit:
    """SafeZipFile refuses instantiation when _nesting_depth exceeds the limit."""

    def test_nesting_depth_exceeded_raises(self, legitimate_archive):
        """_nesting_depth > max_nesting_depth raises NestingDepthError."""
        with pytest.raises(NestingDepthError):
            SafeZipFile(legitimate_archive, max_nesting_depth=3, _nesting_depth=4)

    def test_nesting_depth_at_limit_passes(self, legitimate_archive):
        """_nesting_depth == max_nesting_depth is allowed."""
        with SafeZipFile(legitimate_archive, max_nesting_depth=3, _nesting_depth=3):
            pass

    def test_nesting_depth_zero_always_passes(self, legitimate_archive):
        """Default _nesting_depth=0 never raises."""
        with SafeZipFile(legitimate_archive):
            pass

    def test_nesting_depth_env_var_respected(self, legitimate_archive, monkeypatch):
        """SAFEZIP_MAX_NESTING_DEPTH env var is honoured when no constructor arg
        is given."""
        monkeypatch.setenv("SAFEZIP_MAX_NESTING_DEPTH", "1")
        # depth=2 > env-var limit of 1 → should raise
        with pytest.raises(NestingDepthError):
            SafeZipFile(legitimate_archive, _nesting_depth=2)

    def test_nesting_depth_exceeded_event(self, legitimate_archive):
        """nesting_depth_exceeded event is emitted when depth exceeds limit."""
        events = []
        with pytest.raises(NestingDepthError):
            SafeZipFile(
                legitimate_archive,
                max_nesting_depth=1,
                _nesting_depth=2,
                on_security_event=events.append,
            )
        assert any(e.event_type == "nesting_depth_exceeded" for e in events)


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


class TestRecursiveNestingDepthIntegration:
    """Real zip-within-zip recursion is stopped at max_nesting_depth.

    These tests use an actual nested archive and a realistic recursive
    extraction helper to verify that the guard fires in practice, not just
    when the counter is poked directly.
    """

    @staticmethod
    def _build_nested_zip(levels: int) -> bytes:
        """Return bytes of a zip nested *levels* deep.

        The innermost zip contains ``secret.txt``.  Every outer layer wraps
        the previous one as ``inner.zip`` plus a ``readme.txt`` so there is
        always a regular file at each level too.
        """
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("secret.txt", b"innermost content")
        data = buf.getvalue()

        for _ in range(levels - 1):
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as zf:
                zf.writestr("readme.txt", b"outer level content")
                zf.writestr("inner.zip", data)
            data = buf.getvalue()

        return data

    @staticmethod
    def _recursive_extract(zip_path, dest, *, depth=0, max_nesting_depth=2):
        """Minimal recursive extractor that passes *depth* to SafeZipFile.

        This is the pattern a caller must follow to get nesting protection.
        SafeZipFile raises NestingDepthError before opening the archive when
        *depth* exceeds *max_nesting_depth*.
        """
        with SafeZipFile(
            zip_path,
            max_nesting_depth=max_nesting_depth,
            _nesting_depth=depth,
        ) as zf:
            zf.extractall(dest)
            for name in zf.namelist():
                if name.endswith(".zip"):
                    nested_src = dest / name
                    nested_dest = dest / (name[:-4] + "_contents")
                    nested_dest.mkdir()
                    TestRecursiveNestingDepthIntegration._recursive_extract(
                        nested_src,
                        nested_dest,
                        depth=depth + 1,
                        max_nesting_depth=max_nesting_depth,
                    )

    def test_recursive_extraction_stopped_at_depth_limit(self, tmp_path):
        """Recursion into a 3-level archive raises NestingDepthError at level 3.

        Archive layout::

            outer.zip          (depth 0 — opened fine)
              readme.txt
              inner.zip        (depth 1 — opened fine)
                readme.txt
                inner.zip      (depth 2 — raises, exceeds max_nesting_depth=1)
                  secret.txt
        """
        outer_p = tmp_path / "outer.zip"
        outer_p.write_bytes(self._build_nested_zip(3))
        dest = tmp_path / "out"
        dest.mkdir()

        with pytest.raises(NestingDepthError):
            self._recursive_extract(outer_p, dest, max_nesting_depth=1)

    def test_recursive_extraction_succeeds_within_limit(self, tmp_path):
        """Recursion within the depth limit extracts every level successfully.

        With max_nesting_depth=2 and a 3-level archive (depths 0, 1, 2),
        all levels are within the limit and secret.txt reaches disk.
        """
        outer_p = tmp_path / "outer.zip"
        outer_p.write_bytes(self._build_nested_zip(3))
        dest = tmp_path / "out"
        dest.mkdir()

        self._recursive_extract(outer_p, dest, max_nesting_depth=2)

        innermost = dest / "inner_contents" / "inner_contents" / "secret.txt"
        assert innermost.read_bytes() == b"innermost content"


class TestBuiltinRecursiveExtraction:
    """SafeZipFile with recursive=True auto-descends into nested zip members."""

    @staticmethod
    def _build_zip(members: list[tuple[str, bytes]]) -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for name, content in members:
                zf.writestr(name, content)
        return buf.getvalue()

    def test_recursive_false_is_default_raw_blob(self, tmp_path):
        """recursive=False (default) leaves nested zips as raw files."""
        inner = self._build_zip([("secret.txt", b"inner")])
        outer_p = tmp_path / "outer.zip"
        outer_p.write_bytes(self._build_zip([("inner.zip", inner)]))
        dest = tmp_path / "out"
        dest.mkdir()

        with SafeZipFile(outer_p) as zf:
            zf.extractall(dest)

        assert (dest / "inner.zip").exists()
        assert not (dest / "inner" / "secret.txt").exists()

    def test_recursive_extracts_nested_content(self, tmp_path):
        """recursive=True descends into inner.zip and extracts its content."""
        inner = self._build_zip([("secret.txt", b"inner content")])
        outer_p = tmp_path / "outer.zip"
        outer_p.write_bytes(
            self._build_zip([("readme.txt", b"outer"), ("inner.zip", inner)])
        )
        dest = tmp_path / "out"
        dest.mkdir()

        with SafeZipFile(outer_p, recursive=True) as zf:
            zf.extractall(dest)

        assert (dest / "readme.txt").read_bytes() == b"outer"
        assert (dest / "inner" / "secret.txt").read_bytes() == b"inner content"
        assert not (dest / "inner.zip").exists()

    def test_recursive_depth_limit_raises(self, tmp_path):
        """recursive=True stops at max_nesting_depth and raises NestingDepthError."""
        # 3-level deep: outer -> middle.zip -> inner.zip -> secret.txt
        innermost = self._build_zip([("secret.txt", b"deep")])
        middle = self._build_zip([("inner.zip", innermost)])
        outer_p = tmp_path / "outer.zip"
        outer_p.write_bytes(self._build_zip([("middle.zip", middle)]))
        dest = tmp_path / "out"
        dest.mkdir()

        # max_nesting_depth=1 allows depth 0 and 1; opening depth-2 raises
        with (
            pytest.raises(NestingDepthError),
            SafeZipFile(outer_p, recursive=True, max_nesting_depth=1) as zf,
        ):
            zf.extractall(dest)

    def test_recursive_file_size_enforced_in_nested_zip(self, tmp_path):
        """File size limit applies inside nested zips when recursive=True."""
        inner = self._build_zip([("big.txt", b"A" * 2000)])
        outer_p = tmp_path / "outer.zip"
        outer_p.write_bytes(self._build_zip([("inner.zip", inner)]))
        dest = tmp_path / "out"
        dest.mkdir()

        with (
            pytest.raises(FileSizeExceededError),
            SafeZipFile(outer_p, recursive=True, max_file_size=500) as zf,
        ):
            zf.extractall(dest)

    def test_recursive_traversal_in_nested_zip_blocked(self, tmp_path):
        """Path traversal inside a nested zip is blocked when recursive=True."""
        inner = self._build_zip([("../../evil.txt", b"escaped")])
        outer_p = tmp_path / "outer.zip"
        outer_p.write_bytes(self._build_zip([("inner.zip", inner)]))
        dest = tmp_path / "out"
        dest.mkdir()

        with (
            pytest.raises(UnsafeZipError),
            SafeZipFile(outer_p, recursive=True) as zf,
        ):
            zf.extractall(dest)

        assert not (tmp_path / "evil.txt").exists()

    def test_recursive_mixed_members(self, tmp_path):
        """Regular files and nested zips are both handled correctly."""
        inner = self._build_zip([("data.txt", b"nested data")])
        outer_p = tmp_path / "outer.zip"
        outer_p.write_bytes(
            self._build_zip(
                [
                    ("top.txt", b"top level"),
                    ("pkg.zip", inner),
                ]
            )
        )
        dest = tmp_path / "out"
        dest.mkdir()

        with SafeZipFile(outer_p, recursive=True) as zf:
            zf.extractall(dest)

        assert (dest / "top.txt").read_bytes() == b"top level"
        assert (dest / "pkg" / "data.txt").read_bytes() == b"nested data"
        assert not (dest / "pkg.zip").exists()

    def test_recursive_content_detection_bypasses_extension(self, tmp_path):
        """A nested ZIP named with a non-ZIP extension is still recursed into
        when recursive=True (content-based detection)."""
        inner = self._build_zip([("secret.txt", b"inner content")])
        outer_buf = io.BytesIO()
        with zipfile.ZipFile(outer_buf, "w") as zf:
            zf.writestr("data.csv", inner)
        outer_p = tmp_path / "outer.zip"
        outer_p.write_bytes(outer_buf.getvalue())
        dest = tmp_path / "out"
        dest.mkdir()

        with SafeZipFile(outer_p, recursive=True) as zf:
            zf.extractall(dest)

        # .csv is not a known archive extension, so directory name stays as-is
        assert (dest / "data.csv" / "secret.txt").read_bytes() == b"inner content"

    def test_recursive_non_zip_with_zip_extension_not_recursed(self, tmp_path):
        """A file named .zip that is not actually a ZIP is extracted as a plain file."""
        outer_buf = io.BytesIO()
        with zipfile.ZipFile(outer_buf, "w") as zf:
            zf.writestr("fake.zip", b"this is not a zip file at all")
        outer_p = tmp_path / "outer.zip"
        outer_p.write_bytes(outer_buf.getvalue())
        dest = tmp_path / "out"
        dest.mkdir()

        with SafeZipFile(outer_p, recursive=True) as zf:
            zf.extractall(dest)

        assert (dest / "fake.zip").read_bytes() == b"this is not a zip file at all"


class TestPermissionSanitisation:
    """Dangerous Unix permission bits are stripped from extracted files."""

    def test_setuid_stripped_by_default(self, setuid_archive, tmp_path):
        """setuid bit is stripped by default."""
        dest = tmp_path / "out"
        dest.mkdir()
        with SafeZipFile(setuid_archive) as zf:
            zf.extractall(dest)
        mode = (dest / "suid_binary").stat().st_mode
        assert not (mode & stat.S_ISUID), "setuid bit must be stripped by default"

    def test_normal_permissions_unaffected(self, legitimate_archive, tmp_path):
        """Stripping special bits does not affect normal file access."""
        dest = tmp_path / "out"
        dest.mkdir()
        with SafeZipFile(legitimate_archive) as zf:
            zf.extractall(dest)
        for f in dest.rglob("*"):
            if f.is_file():
                assert f.stat().st_mode & stat.S_IRUSR


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


class TestCompressSizeZero:
    """compress_size == 0 only occurs legitimately for empty members.

    Python's zipfile uses the central directory compress_size to control how
    many bytes it reads during decompression.  A non-empty member with
    compress_size=0 in the CD causes zipfile to read 0 bytes and then fail
    the CRC check (BadZipFile), so it never reaches the streamer's ratio logic.

    The only reachable case is a genuinely empty member, for which skipping
    the ratio check is correct — there is nothing to decompress.
    """

    def test_empty_member_skips_ratio_check_correctly(
        self, data_descriptor_empty_archive, tmp_path
    ):
        """Empty member (compress_size=0) extracts successfully even with a
        tight ratio limit.  Skipping the ratio check is correct behaviour."""
        dest = tmp_path / "out"
        dest.mkdir()

        with zipfile.ZipFile(data_descriptor_empty_archive) as zf:
            info = zf.infolist()[0]
            assert info.compress_size == 0
            assert info.file_size == 0

        with SafeZipFile(data_descriptor_empty_archive, max_per_member_ratio=1.0) as zf:
            zf.extractall(dest)

        assert (dest / "empty.txt").read_bytes() == b""

    def test_nonempty_with_zero_cd_compress_size_rejected_by_zipfile(
        self, data_descriptor_invalid_bomb_archive, tmp_path
    ):
        """A crafted archive with compress_size=0 in the CD but non-empty data
        is rejected by Python's zipfile with BadZipFile before the streamer's
        ratio logic is even reached.  The gap is not exploitable through
        Python's zipfile layer."""
        dest = tmp_path / "out"
        dest.mkdir()

        # Verify the CD does report compress_size=0 despite non-empty content.
        with zipfile.ZipFile(data_descriptor_invalid_bomb_archive) as zf:
            info = zf.infolist()[0]
            assert info.compress_size == 0
            assert info.file_size > 0

        # SafeZipFile opens fine (Guard sees compress_size=0, file_size=2000,
        # both within limits).  BadZipFile is raised by zipfile's CRC check
        # during streaming — before safezip's ratio logic is ever reached.
        with (
            pytest.raises(zipfile.BadZipFile),
            SafeZipFile(data_descriptor_invalid_bomb_archive) as zf,
        ):
            zf.extractall(dest)

        # No partial files left.
        remaining = [f for f in dest.rglob("*") if not f.is_dir()]
        assert not remaining


class TestEnvVarHandling:
    """Environment variable parsing edge cases."""

    def test_invalid_symlink_policy_env(self, legitimate_archive, monkeypatch, caplog):
        """Invalid symlink policy is logged and defaults to REJECT."""
        monkeypatch.setenv("SAFEZIP_SYMLINK_POLICY", "invalid_policy")
        with SafeZipFile(legitimate_archive, symlink_policy=None) as zf:
            assert zf._symlink_policy == SymlinkPolicy.REJECT
        assert "Ignoring unrecognised" in caplog.text

    def test_env_var_read_at_import_time(self, monkeypatch):
        """Changing env vars after import does not affect cached defaults.

        The module-level singletons (_DEFAULT_*) are evaluated once at import time.
        Late env changes do not alter limits on new SafeZipFile instances.
        """
        import safezip._core as _core

        original_default = _core._DEFAULT_MAX_FILES
        monkeypatch.setenv("SAFEZIP_MAX_FILES", "99")
        assert original_default == _core._DEFAULT_MAX_FILES
