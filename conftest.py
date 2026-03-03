"""
Pytest fixtures for documentation testing.

DO NOT ADD OTHER FIXTURES HERE.
"""

import io
import zipfile
from pathlib import Path

import pytest


@pytest.fixture()
def file_zip(tmp_path):
    """A valid ZIP file named file.zip."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("hello.txt", b"Hello, world!\n")
    p = Path("path/to") / "file.zip"
    p.write_bytes(buf.getvalue())
    return p


@pytest.fixture()
def nested_file_zip(tmp_path):
    """archive.zip containing readme.txt and data.zip (which contains report.csv).

    Matches the README 'Recursive extraction' example exactly::

        archive.zip
          readme.txt
          data.zip
            report.csv
    """
    inner_buf = io.BytesIO()
    with zipfile.ZipFile(inner_buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("report.csv", b"id,value\n1,100\n")

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("readme.txt", b"Archive readme\n")
        zf.writestr("data.zip", inner_buf.getvalue())

    p = Path("path/to") / "archive.zip"
    p.write_bytes(buf.getvalue())
    return p
