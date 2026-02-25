"""Tests for Phase B: path resolution and symlink policy (the Sandbox)."""

import pytest

from safezip import UnsafeZipError
from safezip._sandbox import resolve_member_path

__author__ = "Artur Barseghyan <artur.barseghyan@gmail.com>"
__copyright__ = "2026 Artur Barseghyan"
__license__ = "Apache-2.0"


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


class TestPathLengthLimit:
    """resolve_member_path rejects excessively long paths."""

    def test_very_long_filename_rejected(self, tmp_path):
        long_name = "a" * 5000 + ".txt"
        with pytest.raises(UnsafeZipError, match="too long"):
            resolve_member_path(tmp_path, long_name)
