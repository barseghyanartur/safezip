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
