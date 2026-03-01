import struct
import zipfile
import zlib

import pytest

from safezip import SafeZipFile

__author__ = "Artur Barseghyan <artur.barseghyan@gmail.com>"
__copyright__ = "2026 Artur Barseghyan"
__license__ = "MIT"


@pytest.fixture()
def data_descriptor_empty_archive(tmp_path):
    """Valid ZIP with empty member using data descriptor (compress_size=0)."""
    comp_data = b""
    comp_size = 0
    uncomp_size = 0
    crc = 0

    filename = b"empty.txt"
    fname_len = len(filename)

    # Local header: sizes=0, flags=0x08, method=0 (stored, since empty)
    local_header = (
        struct.pack(
            "<4sHHHHHIIIHH",
            b"PK\x03\x04",
            20,
            0x08,
            0,  # stored
            0,
            0,
            0,
            0,
            0,
            fname_len,
            0,
        )
        + filename
    )

    # Data descriptor
    descriptor = struct.pack("<4sIII", b"PK\x07\x08", crc, comp_size, uncomp_size)

    local_with_desc = local_header + comp_data + descriptor

    # Central header: sizes=0, flags=0x08
    central_header = (
        struct.pack(
            "<4sHHHHHHIIIHHHHHII",
            b"PK\x01\x02",
            0x0314,
            20,
            0x08,
            0,
            0,
            0,
            crc,
            comp_size,
            uncomp_size,
            fname_len,
            0,
            0,
            0,
            0,
            0,
            0,
        )
        + filename
    )

    cd_offset = len(local_with_desc)
    cd_size = len(central_header)
    eocd = struct.pack("<4sHHHHIIH", b"PK\x05\x06", 0, 0, 1, 1, cd_size, cd_offset, 0)

    archive_bytes = local_with_desc + central_header + eocd
    p = tmp_path / "dd_empty.zip"
    p.write_bytes(archive_bytes)
    return p


@pytest.fixture()
def data_descriptor_invalid_bomb_archive(tmp_path):
    """
    Invalid ZIP with non-empty member, data descriptor, but CD compress_size=0.
    """
    uncomp_data = b"\x00" * 2000
    compressor = zlib.compressobj(
        zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, -zlib.MAX_WBITS
    )
    comp_data = compressor.compress(uncomp_data) + compressor.flush()
    comp_size = len(comp_data)
    uncomp_size = len(uncomp_data)
    crc = zlib.crc32(uncomp_data)

    filename = b"bomb.txt"
    fname_len = len(filename)

    # Local header: sizes=0, flags=0x08, method=8 (deflate)
    local_header = (
        struct.pack(
            "<4sHHHHHIIIHH",
            b"PK\x03\x04",
            20,
            0x08,
            8,
            0,
            0,
            0,
            0,
            0,
            fname_len,
            0,
        )
        + filename
    )

    # Data descriptor with real sizes
    descriptor = struct.pack("<4sIII", b"PK\x07\x08", crc, comp_size, uncomp_size)

    local_with_desc = local_header + comp_data + descriptor

    # Central header: compress_size=0 (invalid mismatch), uncomp_size=real
    central_header = (
        struct.pack(
            "<4sHHHHHHIIIHHHHHII",
            b"PK\x01\x02",
            0x0314,
            20,
            0x08,
            8,
            0,
            0,
            crc,
            0,  # invalid comp_size=0
            uncomp_size,
            fname_len,
            0,
            0,
            0,
            0,
            0,
            0,
        )
        + filename
    )

    cd_offset = len(local_with_desc)
    cd_size = len(central_header)
    eocd = struct.pack("<4sHHHHIIH", b"PK\x05\x06", 0, 0, 1, 1, cd_size, cd_offset, 0)

    archive_bytes = local_with_desc + central_header + eocd
    p = tmp_path / "dd_invalid_bomb.zip"
    p.write_bytes(archive_bytes)
    return p


class TestCompressSizeZero:
    """compress_size == 0 only occurs legitimately for empty members.

    Python's zipfile uses the central directory compress_size to control how
    many bytes it reads during decompression. A non-empty member with
    compress_size=0 in the CD causes zipfile to read 0 bytes and then fail
    the CRC check (BadZipFile), so it never reaches the streamer's ratio logic.

    The only reachable case is a genuinely empty member, for which skipping
    the ratio check is correct — there is nothing to decompress.
    """

    def test_empty_member_skips_ratio_check_correctly(
        self, data_descriptor_empty_archive, tmp_path
    ):
        """Empty member (compress_size=0) extracts successfully even with a
        tight ratio limit. Skipping the ratio check is correct behavior."""
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
        ratio logic is even reached. The gap is not exploitable through
        Python's zipfile layer."""
        dest = tmp_path / "out"
        dest.mkdir()

        # Verify the CD does report compress_size=0 despite non-empty content
        with zipfile.ZipFile(data_descriptor_invalid_bomb_archive) as zf:
            info = zf.infolist()[0]
            assert info.compress_size == 0
            assert info.file_size > 0

        # SafeZipFile opens fine (Guard sees compress_size=0, file_size=2000,
        # both within limits). BadZipFile is raised by zipfile's CRC check
        # during streaming — before safezip's ratio logic is ever reached.
        with (
            pytest.raises(zipfile.BadZipFile),
            SafeZipFile(data_descriptor_invalid_bomb_archive) as zf,
        ):
            zf.extractall(dest)

        # No partial files left
        remaining = [f for f in dest.rglob("*") if not f.is_dir()]
        assert not remaining
