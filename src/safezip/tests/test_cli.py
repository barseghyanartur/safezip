"""Tests for the safezip CLI."""

import io
import zipfile
from unittest.mock import patch

import pytest

from safezip.cli._main import main

__author__ = "Artur Barseghyan <artur.barseghyan@gmail.com>"
__copyright__ = "2026 Artur Barseghyan"
__license__ = "MIT"


@pytest.fixture()
def simple_archive(tmp_path):
    """A simple valid ZIP archive."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("file1.txt", b"content1\n")
        zf.writestr("dir/file2.txt", b"content2\n")
    p = tmp_path / "simple.zip"
    p.write_bytes(buf.getvalue())
    return p


class TestExtractCommand:
    """Tests for the extract command."""

    def test_extract_basic(self, simple_archive, tmp_path, capsys):
        """Basic extraction works."""
        dest = tmp_path / "out"
        with patch("sys.argv", ["safezip", "extract", str(simple_archive), str(dest)]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0

        assert (dest / "file1.txt").read_text() == "content1\n"
        assert (dest / "dir" / "file2.txt").read_text() == "content2\n"
        captured = capsys.readouterr()
        assert "Extracted to" in captured.out

    def test_extract_with_max_file_size(self, simple_archive, tmp_path):
        """Extract with --max-file-size flag."""
        dest = tmp_path / "out"
        with patch(
            "sys.argv",
            [
                "safezip",
                "extract",
                str(simple_archive),
                str(dest),
                "--max-file-size",
                "1000",
            ],
        ):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0

        assert (dest / "file1.txt").exists()

    def test_extract_with_max_files(self, simple_archive, tmp_path):
        """Extract with --max-files flag."""
        dest = tmp_path / "out"
        with patch(
            "sys.argv",
            [
                "safezip",
                "extract",
                str(simple_archive),
                str(dest),
                "--max-files",
                "10",
            ],
        ):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0

        assert (dest / "file1.txt").exists()

    def test_extract_with_symlink_policy(self, simple_archive, tmp_path):
        """Extract with --symlink-policy flag."""
        dest = tmp_path / "out"
        with patch(
            "sys.argv",
            [
                "safezip",
                "extract",
                str(simple_archive),
                str(dest),
                "--symlink-policy",
                "reject",
            ],
        ):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0

        assert (dest / "file1.txt").exists()

    def test_extract_with_recursive_flag(self, simple_archive, tmp_path):
        """Extract with --recursive flag."""
        dest = tmp_path / "out"
        with patch(
            "sys.argv",
            [
                "safezip",
                "extract",
                str(simple_archive),
                str(dest),
                "--recursive",
            ],
        ):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0

        assert (dest / "file1.txt").exists()

    def test_extract_nonexistent_archive(self, tmp_path, capsys):
        """Extract fails with nonexistent archive."""
        dest = tmp_path / "out"
        with patch("sys.argv", ["safezip", "extract", "/nonexistent.zip", str(dest)]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1

        captured = capsys.readouterr()
        assert "error:" in captured.err

    def test_extract_creates_destination(self, simple_archive, tmp_path):
        """Extract creates destination directory if it doesn't exist."""
        dest = tmp_path / "nested" / "out"
        with patch("sys.argv", ["safezip", "extract", str(simple_archive), str(dest)]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0

        assert dest.exists()
        assert (dest / "file1.txt").exists()

    def test_extract_zipslip_rejected(self, zipslip_archive, tmp_path, capsys):
        """Extract rejects ZipSlip archive."""
        dest = tmp_path / "out"
        with patch("sys.argv", ["safezip", "extract", str(zipslip_archive), str(dest)]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1

        captured = capsys.readouterr()
        assert "error:" in captured.err

    def test_extract_zipbomb_rejected(self, high_ratio_archive, tmp_path, capsys):
        """Extract rejects ZIP bomb."""
        dest = tmp_path / "out"
        with patch(
            "sys.argv",
            [
                "safezip",
                "extract",
                str(high_ratio_archive),
                str(dest),
                "--max-per-member-ratio",
                "10",
            ],
        ):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1

        captured = capsys.readouterr()
        assert "error:" in captured.err

    def test_extract_too_many_files_rejected(
        self, many_files_archive, tmp_path, capsys
    ):
        """Extract rejects archive with too many files."""
        dest = tmp_path / "out"
        with patch(
            "sys.argv",
            [
                "safezip",
                "extract",
                str(many_files_archive),
                str(dest),
                "--max-files",
                "100",
            ],
        ):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1

        captured = capsys.readouterr()
        assert "error:" in captured.err

    def test_extract_null_byte_filename_rejected(
        self, null_byte_filename_archive, tmp_path, capsys
    ):
        """Extract rejects archive with null byte in filename."""
        dest = tmp_path / "out"
        with patch(
            "sys.argv",
            ["safezip", "extract", str(null_byte_filename_archive), str(dest)],
        ):
            with pytest.raises(SystemExit) as exc_info:
                main()
            # Can exit with 1 due to either MalformedArchiveError (null byte)
            # or BadZipFile (CRC error from crafted archive)
            assert exc_info.value.code == 1

        captured = capsys.readouterr()
        assert "error:" in captured.err


class TestListCommand:
    """Tests for the list command."""

    def test_list_basic(self, simple_archive, capsys):
        """List command shows archive members."""
        with patch("sys.argv", ["safezip", "list", str(simple_archive)]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0

        captured = capsys.readouterr()
        assert "file1.txt" in captured.out
        assert "dir/file2.txt" in captured.out

    def test_list_nonexistent_archive(self, capsys):
        """List fails with nonexistent archive."""
        with patch("sys.argv", ["safezip", "list", "/nonexistent.zip"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1

        captured = capsys.readouterr()
        assert "error:" in captured.err


class TestVersionFlag:
    """Tests for --version flag."""

    def test_version_flag(self, capsys):
        """--version flag displays version."""
        with patch("sys.argv", ["safezip", "--version"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0

        captured = capsys.readouterr()
        assert "safezip" in captured.out
