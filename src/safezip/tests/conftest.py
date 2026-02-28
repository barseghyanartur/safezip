"""Pytest fixtures: factory functions that craft malicious ZIP archives."""

import io
import stat
import struct
import zipfile

import pytest

__author__ = "Artur Barseghyan <artur.barseghyan@gmail.com>"
__copyright__ = "2026 Artur Barseghyan"
__license__ = "MIT"
__all__ = (
    "zipslip_archive",
    "absolute_path_archive",
    "unicode_traversal_archive",
    "high_ratio_archive",
    "many_files_archive",
    "null_byte_filename_archive",
    "zip64_inconsistency_archive",
    "legitimate_archive",
    "symlink_archive",
)


# ---------------------------------------------------------------------------
# Archive factory helpers
# ---------------------------------------------------------------------------


def _make_zip_bytes(entries: list[tuple[str, bytes]]) -> bytes:
    """Create a ZIP in memory from (filename, content) pairs."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, content in entries:
            info = zipfile.ZipInfo(name)
            zf.writestr(info, content)
    return buf.getvalue()


def _make_zip_bytes_stored(entries: list[tuple[str, bytes]]) -> bytes:
    """Create a stored (uncompressed) ZIP in memory."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
        for name, content in entries:
            info = zipfile.ZipInfo(name)
            zf.writestr(info, content)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def zipslip_archive(tmp_path):
    """A ZIP whose sole entry has a path-traversal filename."""
    data = _make_zip_bytes([("../../evil.txt", b"evil content")])
    p = tmp_path / "zipslip.zip"
    p.write_bytes(data)
    return p


@pytest.fixture()
def absolute_path_archive(tmp_path):
    """A ZIP with an absolute Unix-style path entry."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        info = zipfile.ZipInfo("/etc/passwd")
        zf.writestr(info, "root:x:0:0:root:/root:/bin/bash\n")
    data = buf.getvalue()
    p = tmp_path / "absolute.zip"
    p.write_bytes(data)
    return p


@pytest.fixture()
def unicode_traversal_archive(tmp_path):
    """A ZIP with combining Unicode characters that NFC-normalises to a path
    still containing a ``..`` traversal component.

    The filename ``e\\u0301vil/../../escape.txt`` uses U+0301 COMBINING ACUTE
    ACCENT (NFD form of ``é``).  After Unicode NFC normalisation the combining
    accent is folded into the precomposed ``é``, yielding
    ``évil/../../escape.txt``.  The ``..`` components are unaffected by NFC
    and must still be detected and rejected.
    """
    # e + COMBINING ACUTE ACCENT → é after NFC; the traversal stays intact
    data = _make_zip_bytes([("e\u0301vil/../../escape.txt", b"escaped")])
    p = tmp_path / "unicode_traversal.zip"
    p.write_bytes(data)
    return p


@pytest.fixture()
def high_ratio_archive(tmp_path):
    """A ZIP whose content compresses at a very high ratio (zeros)."""
    # 2 MiB of zeros → compressed to ~2 KB → ratio ~1000:1
    data_bytes = b"\x00" * (2 * 1024 * 1024)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("zeros.bin", data_bytes)
    p = tmp_path / "bomb.zip"
    p.write_bytes(buf.getvalue())
    return p


@pytest.fixture()
def many_files_archive(tmp_path):
    """A ZIP with more entries than the default max_files limit allows."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for i in range(15_000):
            zf.writestr(f"file_{i:05d}.txt", b"x")
    p = tmp_path / "many_files.zip"
    p.write_bytes(buf.getvalue())
    return p


@pytest.fixture()
def null_byte_filename_archive(tmp_path):
    """A ZIP with a null byte injected into a filename via raw struct manipulation.

    Python's zipfile won't let us write such names directly, so we craft the
    raw bytes: a minimal ZIP with one entry whose filename contains \\x00.
    """
    # Minimal ZIP structure:
    # Local file header + file data + central directory + end of central directory
    filename = b"safe\x00../../etc/passwd"
    fname_len = len(filename)
    content = b"evil"
    content_len = len(content)

    # Local file header (signature 0x04034b50)
    local_header = (
        struct.pack(
            "<4s2H3H4s2I2H",
            b"PK\x03\x04",  # signature
            20,  # version needed
            0,  # flags
            0,  # compression (stored)
            0,  # mod time
            0,  # mod date
            b"\x00\x00\x00\x00",  # CRC-32
            content_len,  # compressed size
            content_len,  # uncompressed size
            fname_len,  # filename length
            0,  # extra field length
        )
        + filename
        + content
    )

    local_offset = 0

    # Central directory header (signature 0x02014b50)
    # Format: 4s sig | 6H (ver_made,ver_needed,flags,compress,mod_time,mod_date) |
    #         4s CRC | 2I (comp_size,uncomp_size) |
    #         5H (fname_len,extra_len,comment_len,disk_start,int_attr) |
    #         2I (ext_attr, offset)  → 17 items, 46 bytes
    central_header = (
        struct.pack(
            "<4s6H4s2I5H2I",
            b"PK\x01\x02",  # signature
            0x031E,  # version made by (Unix, v30)
            20,  # version needed
            0,  # flags
            0,  # compression
            0,  # mod time
            0,  # mod date
            b"\x00\x00\x00\x00",  # CRC-32
            content_len,  # compressed size (I)
            content_len,  # uncompressed size (I)
            fname_len,  # filename length
            0,  # extra field length
            0,  # file comment length
            0,  # disk number start
            0,  # internal file attributes
            0,  # external file attributes (I)
            local_offset,  # relative offset of local header (I)
        )
        + filename
    )

    central_offset = len(local_header)
    central_size = len(central_header)

    # End of central directory record (signature 0x06054b50)
    eocd = struct.pack(
        "<4s4H2IH",
        b"PK\x05\x06",  # signature
        0,  # disk number
        0,  # disk with central dir
        1,  # entries on this disk
        1,  # total entries
        central_size,  # size of central directory
        central_offset,  # offset of central directory
        0,  # comment length
    )

    data = local_header + central_header + eocd
    p = tmp_path / "nullbyte.zip"
    p.write_bytes(data)
    return p


@pytest.fixture()
def zip64_inconsistency_archive(tmp_path):
    """A ZIP with a ZIP64 extra field that disagrees with the central directory.

    We craft a minimal archive where the ZIP64 extra field reports a size of
    999_999_999 bytes but the 32-bit central directory field reports 100 bytes.
    Python will use the 32-bit value (100), but our ZIP64 check sees 999_999_999
    and raises MalformedArchiveError.
    """
    filename = b"test.txt"
    fname_len = len(filename)
    content = b"A" * 100

    # ZIP64 extra field reporting a huge uncompressed size
    zip64_uncompressed = 999_999_999
    zip64_extra = struct.pack(
        "<HHQ",
        0x0001,  # ZIP64 tag
        8,  # size of following data (8 bytes = one uint64)
        zip64_uncompressed,  # uncompressed size (disagrees with 32-bit field below)
    )
    extra_len = len(zip64_extra)

    # Local file header - 32-bit uncompressed size = 100 (not sentinel)
    local_header = (
        struct.pack(
            "<4s2H3H4s2I2H",
            b"PK\x03\x04",
            20,
            0,
            0,
            0,
            0,
            b"\x00\x00\x00\x00",
            len(content),
            len(content),  # 32-bit uncompressed size = 100
            fname_len,
            extra_len,
        )
        + filename
        + zip64_extra
        + content
    )

    local_offset = 0

    # Central directory header - 32-bit uncompressed size = 100 (not sentinel)
    # Format: 4s | 6H | 4s CRC | 2I (comp,uncomp) | 5H | 2I → 17 items, 46 bytes
    central_header = (
        struct.pack(
            "<4s6H4s2I5H2I",
            b"PK\x01\x02",
            0x031E,
            20,
            0,
            0,
            0,
            0,
            b"\x00\x00\x00\x00",
            len(content),  # compressed size (I)
            len(content),  # 32-bit uncompressed size = 100 (I, not sentinel)
            fname_len,
            extra_len,
            0,  # comment length
            0,  # disk number start
            0,  # internal attributes
            0,  # external attributes (I)
            local_offset,  # offset of local header (I)
        )
        + filename
        + zip64_extra
    )

    central_offset = len(local_header)
    central_size = len(central_header)

    eocd = struct.pack(
        "<4s4H2IH",
        b"PK\x05\x06",
        0,
        0,
        1,
        1,
        central_size,
        central_offset,
        0,
    )

    data = local_header + central_header + eocd
    p = tmp_path / "zip64_inconsistency.zip"
    p.write_bytes(data)
    return p


@pytest.fixture()
def legitimate_archive(tmp_path):
    """A well-formed, safe archive with a few text files."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("hello.txt", b"Hello, world!\n")
        zf.writestr("subdir/data.txt", b"Some data\n")
        zf.writestr("subdir/nested/deep.txt", b"Deep file\n")
    p = tmp_path / "legitimate.zip"
    p.write_bytes(buf.getvalue())
    return p


@pytest.fixture()
def symlink_archive(tmp_path):
    """A ZIP containing one regular file and one Unix symlink entry.

    The symlink entry's content (the link target) is ``../escape.txt``,
    which would point outside the extraction root if followed blindly.
    The entry is flagged as a symlink via the upper 16 bits of
    ``ZipInfo.external_attr`` (Unix mode ``S_IFLNK | 0o755``).
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
        # A harmless regular file that must always be extractable
        zf.writestr("readme.txt", b"safe content\n")
        # Symlink entry: mode S_IFLNK | 0o755, content = link target
        sym = zipfile.ZipInfo("link.txt")
        sym.external_attr = (stat.S_IFLNK | 0o755) << 16
        zf.writestr(sym, "../escape.txt")
    p = tmp_path / "symlink.zip"
    p.write_bytes(buf.getvalue())
    return p
