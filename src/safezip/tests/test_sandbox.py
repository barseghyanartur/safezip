"""Tests for Phase B: path resolution and symlink policy (the Sandbox)."""

import os

import pytest

from safezip import UnsafeZipError
from safezip._sandbox import resolve_member_path

__author__ = "Artur Barseghyan <artur.barseghyan@gmail.com>"
__copyright__ = "2026 Artur Barseghyan"
__license__ = "MIT"


class TestPathTraversal:
    """resolve_member_path rejects all forms of path traversal."""

    def test_dotdot_relative(self, tmp_path):
        with pytest.raises(UnsafeZipError, match="traversal"):
            resolve_member_path(tmp_path, "../../evil.txt")

    def test_dotdot_in_middle(self, tmp_path):
        with pytest.raises(UnsafeZipError, match="traversal"):
            resolve_member_path(tmp_path, "subdir/../../../evil.txt")

    def test_dotdot_windows_style(self, tmp_path):
        with pytest.raises(UnsafeZipError, match="traversal"):
            resolve_member_path(tmp_path, "subdir\\..\\..\\evil.txt")

    def test_absolute_unix_path(self, tmp_path):
        with pytest.raises(UnsafeZipError):
            resolve_member_path(tmp_path, "/etc/passwd")

    def test_absolute_windows_path(self, tmp_path):
        with pytest.raises(UnsafeZipError):
            resolve_member_path(tmp_path, "C:\\Windows\\System32\\cmd.exe")

    def test_unc_path(self, tmp_path):
        with pytest.raises(UnsafeZipError):
            resolve_member_path(tmp_path, "//server/share/evil.txt")


class TestNullByte:
    """resolve_member_path rejects filenames with null bytes."""

    def test_null_byte_rejected(self, tmp_path):
        with pytest.raises(UnsafeZipError):
            resolve_member_path(tmp_path, "safe\x00../../etc/passwd")

    def test_null_byte_at_start(self, tmp_path):
        with pytest.raises(UnsafeZipError):
            resolve_member_path(tmp_path, "\x00evil.txt")


class TestLegitimateFilenames:
    """resolve_member_path accepts well-formed filenames."""

    def test_simple_filename(self, tmp_path):
        result = resolve_member_path(tmp_path, "hello.txt")
        assert result == tmp_path / "hello.txt"

    def test_nested_filename(self, tmp_path):
        result = resolve_member_path(tmp_path, "subdir/data.txt")
        assert result == tmp_path / "subdir" / "data.txt"

    def test_deep_nested(self, tmp_path):
        result = resolve_member_path(tmp_path, "a/b/c/d/e.txt")
        assert result == tmp_path / "a" / "b" / "c" / "d" / "e.txt"

    def test_windows_separator_legitimate(self, tmp_path):
        """Windows-style separators are normalised to forward slashes."""
        result = resolve_member_path(tmp_path, "subdir\\file.txt")
        assert result == tmp_path / "subdir" / "file.txt"

    def test_result_is_inside_base(self, tmp_path):
        result = resolve_member_path(tmp_path, "subdir/file.txt")
        assert str(result).startswith(str(tmp_path))

    def test_unicode_filename(self, tmp_path):
        result = resolve_member_path(tmp_path, "données/résumé.txt")
        assert result.name == "résumé.txt"

    def test_leading_slash_rejected(self, tmp_path):
        """A leading slash is treated as an absolute path and rejected."""
        with pytest.raises(UnsafeZipError, match="Absolute path"):
            resolve_member_path(tmp_path, "/file.txt")

    def test_dot_components_stripped(self, tmp_path):
        result = resolve_member_path(tmp_path, "./subdir/./file.txt")
        assert result == tmp_path / "subdir" / "file.txt"

    def test_empty_parts_stripped(self, tmp_path):
        result = resolve_member_path(tmp_path, "subdir//file.txt")
        assert result == tmp_path / "subdir" / "file.txt"


class TestDrivePrefixBypass:
    """resolve_member_path rejects ZipSlip bypass via Windows drive-prefix stripping."""

    def test_dotdot_after_drive_prefix_double(self, tmp_path):
        with pytest.raises(UnsafeZipError, match="traversal"):
            resolve_member_path(tmp_path, "C:../C:../etc/target")

    def test_dotdot_after_drive_prefix_lowercase(self, tmp_path):
        with pytest.raises(UnsafeZipError, match="traversal"):
            resolve_member_path(tmp_path, "c:../foo")

    def test_dotdot_after_drive_prefix_various(self, tmp_path):
        payloads = [
            "C:../etc/passwd",
            "c:../foo",
            "Z:../../../etc/shadow",
        ]
        for payload in payloads:
            with pytest.raises(UnsafeZipError, match="traversal"):
                resolve_member_path(tmp_path, payload)

    def test_backslash_drive_prefix(self, tmp_path):
        """Backslash normalised to slash before drive-prefix stripping."""
        with pytest.raises(UnsafeZipError, match="traversal"):
            resolve_member_path(tmp_path, "C:..\\..\\foo")

    def test_bare_drive_prefix_double_dot(self, tmp_path):
        """Single part that is exactly 'X:..' strips to '..'."""
        with pytest.raises(UnsafeZipError, match="traversal"):
            resolve_member_path(tmp_path, "X:..")

    def test_drive_prefix_multiple_traversal(self, tmp_path):
        """Multiple '..' components after stripping are caught immediately."""
        with pytest.raises(UnsafeZipError, match="traversal"):
            resolve_member_path(tmp_path, "A:../../etc/passwd")

    def test_drive_prefix_legitimate_relative(self, tmp_path):
        """Stripping 'C:' from a valid relative path succeeds."""
        result = resolve_member_path(tmp_path, "C:subdir/file.txt")
        assert result == tmp_path / "subdir" / "file.txt"

    def test_bare_drive_no_suffix(self, tmp_path):
        """Bare drive 'C:' strips to empty string → empty path error."""
        with pytest.raises(UnsafeZipError, match="empty"):
            resolve_member_path(tmp_path, "C:")


class TestResolveContainment:
    """resolve_member_path uses .resolve() to catch symlink-based escapes."""

    @pytest.mark.skipif(
        not hasattr(os, "symlink"),
        reason="os.symlink not available",
    )
    def test_symlink_in_base_dir_escapes(self, tmp_path):
        """Path resolving through a symlink outside base is rejected."""
        real_dir = tmp_path / "real_outside"
        real_dir.mkdir()
        (real_dir / "secret.txt").write_text("leaked")

        base = tmp_path / "base"
        base.mkdir()
        evil_link = base / "subdir"
        os.symlink(str(real_dir), str(evil_link))

        with pytest.raises(UnsafeZipError, match="escapes base"):
            resolve_member_path(base, "subdir/secret.txt")

    @pytest.mark.skipif(
        not hasattr(os, "symlink"),
        reason="os.symlink not available",
    )
    def test_base_is_symlink(self, tmp_path):
        """Base directory is itself a symlink — both sides resolve identically."""
        real_base = tmp_path / "real_base"
        real_base.mkdir()

        link_base = tmp_path / "link_base"
        os.symlink(str(real_base), str(link_base))

        result = resolve_member_path(link_base, "file.txt")
        # Return value uses the symlink name; resolved paths must agree.
        assert result == link_base / "file.txt"
        assert result.resolve() == real_base.resolve() / "file.txt"

    @pytest.mark.skipif(
        not hasattr(os, "symlink"),
        reason="os.symlink not available",
    )
    def test_nested_symlink_component(self, tmp_path):
        """Chained symlinks resolving outside base are rejected."""
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "data.txt").write_text("secret")

        base = tmp_path / "base"
        base.mkdir()
        # a -> b -> outside
        b_dir = tmp_path / "b"
        b_dir.mkdir()
        os.symlink(str(outside), str(b_dir / "secret"))
        os.symlink(str(b_dir), str(base / "a"))

        with pytest.raises(UnsafeZipError, match="escapes base"):
            resolve_member_path(base, "a/secret/data.txt")


class TestPathLengthLimit:
    """resolve_member_path rejects excessively long paths."""

    def test_very_long_filename_rejected(self, tmp_path):
        long_name = "a" * 5000 + ".txt"
        with pytest.raises(UnsafeZipError, match="too long"):
            resolve_member_path(tmp_path, long_name)
