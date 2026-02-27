=======
safezip
=======
.. image:: https://raw.githubusercontent.com/barseghyanartur/safezip/main/docs/_static/safezip_logo.webp
   :alt: SafeZip Logo
   :align: center

Hardened ZIP extraction for Python - secure by default.

.. image:: https://img.shields.io/pypi/v/safezip.svg
   :target: https://pypi.python.org/pypi/safezip
   :alt: PyPI Version

.. image:: https://img.shields.io/pypi/pyversions/safezip.svg
   :target: https://pypi.python.org/pypi/safezip/
   :alt: Supported Python versions

.. image:: https://github.com/barseghyanartur/safezip/actions/workflows/test.yml/badge.svg?branch=main
   :target: https://github.com/barseghyanartur/safezip/actions
   :alt: Build Status

.. image:: https://readthedocs.org/projects/safezip/badge/?version=latest
    :target: http://safezip.readthedocs.io
    :alt: Documentation Status

.. image:: https://img.shields.io/badge/docs-llms.txt-blue
    :target: https://safezip.readthedocs.io/en/latest/llms.txt
    :alt: llms.txt - documentation for LLMs

.. image:: https://img.shields.io/badge/license-MIT-blue.svg
   :target: https://github.com/barseghyanartur/safezip/#License
   :alt: MIT

.. image:: https://coveralls.io/repos/github/barseghyanartur/safezip/badge.svg?branch=main&service=github
    :target: https://coveralls.io/github/barseghyanartur/safezip?branch=main
    :alt: Coverage

``safezip`` is a zero-dependency, production-grade wrapper around Python's
``zipfile`` module that defends against the most common ZIP-based attacks:
ZipSlip path traversal, ZIP bombs, and malformed/crafted archives.

Features
========

- **ZipSlip protection** - relative traversal, absolute paths, Windows UNC
  paths, Unicode lookalike attacks, and null bytes in filenames are all
  blocked.
- **ZIP bomb protection** - per-member and cumulative decompression ratio
  limits abort extraction before runaway decompression can exhaust disk or
  memory.
- **File size limits** - per-member and total extraction size limits enforced
  at stream time (not based on untrusted header values).
- **ZIP64 consistency checks** - crafted archives with inconsistent ZIP64
  extra fields are rejected before decompression begins.
- **Symlink policy** - configurable: ``REJECT`` (default), ``IGNORE``, or
  ``RESOLVE_INTERNAL`` (full chain verification).
- **Atomic writes** - every member is written to a temporary file first;
  the destination is only created after all checks pass.  No partial files
  are left on disk after a security abort.
- **Secure by default** - all limits are active without any configuration.
- **Zero dependencies** - standard library only.
- **Environment variable overrides** - all numeric limits can be set via
  ``SAFEZIP_*`` environment variables for containerised deployments.

Prerequisites
=============

Python 3.10 or later.  No additional packages required.

Installation
============
With ``uv``:

.. code-block:: sh

    uv pip install safezip

Or with ``pip``:

.. code-block:: sh

    pip install safezip

Quick start
===========

Drop-in replacement for the common ``zipfile`` extraction pattern:

.. pytestfixture: file_zip
.. code-block:: python
    :name: test_safe_extract

    from safezip import safe_extract

    safe_extract("path/to/file.zip", "/var/files/extracted/")

Or use the ``SafeZipFile`` context manager for more control:

.. pytestfixture: file_zip
.. code-block:: python
    :name: test_safe_zipfile

    from safezip import SafeZipFile

    with SafeZipFile("path/to/file.zip") as zf:
        print(zf.namelist())
        zf.extractall("/var/files/extracted/")

Custom limits
=============

.. pytestfixture: file_zip
.. code-block:: python
    :name: test_custom_limits

    from safezip import SafeZipFile

    with SafeZipFile(
        "path/to/file.zip",
        max_file_size=100 * 1024 * 1024,   # 100 MiB per member
        max_total_size=500 * 1024 * 1024,  # 500 MiB total
        max_files=1_000,
        max_per_member_ratio=50.0,
        max_total_ratio=50.0,
    ) as zf:
        zf.extractall("/var/files/extracted/")

Security event monitoring
=========================

.. pytestfixture: file_zip
.. code-block:: python
    :name: test_security_event_monitoring

    from safezip import SafeZipFile, SecurityEvent

    def my_monitor(event: SecurityEvent) -> None:
        print(f"[safezip] {event.event_type} archive={event.archive_hash}")

    with SafeZipFile("path/to/file.zip", on_security_event=my_monitor) as zf:
        zf.extractall("/var/files/extracted/")

Environment variable overrides
==============================

All numeric limits can be overridden without changing code:

.. code-block:: sh

    export SAFEZIP_MAX_FILE_SIZE=104857600    # 100 MiB
    export SAFEZIP_MAX_TOTAL_SIZE=524288000   # 500 MiB
    export SAFEZIP_MAX_FILES=1000
    export SAFEZIP_MAX_PER_MEMBER_RATIO=50
    export SAFEZIP_MAX_TOTAL_RATIO=50

Default limits
==============

+--------------------------+------------+
| Parameter                | Default    |
+==========================+============+
| ``max_file_size``        | 1 GiB      |
+--------------------------+------------+
| ``max_total_size``       | 5 GiB      |
+--------------------------+------------+
| ``max_files``            | 10 000     |
+--------------------------+------------+
| ``max_per_member_ratio`` | 200        |
+--------------------------+------------+
| ``max_total_ratio``      | 200        |
+--------------------------+------------+
| ``max_nesting_depth``    | 3          |
+--------------------------+------------+
| ``symlink_policy``       | REJECT     |
+--------------------------+------------+

Testing
=======

All tests run inside Docker to prevent accidental pollution of the host system:

.. code-block:: sh

    make test

To test a specific Python version:

.. code-block:: sh

    make test-env ENV=py312

Writing documentation
=====================

Keep the following hierarchy:

.. code-block:: text

    =====
    title
    =====

    header
    ======

    sub-header
    ----------

    sub-sub-header
    ~~~~~~~~~~~~~~

    sub-sub-sub-header
    ^^^^^^^^^^^^^^^^^^

    sub-sub-sub-sub-header
    ++++++++++++++++++++++

    sub-sub-sub-sub-sub-header
    **************************

License
=======

MIT

Support
=======
For security issues contact me at the e-mail given in the `Author`_ section.

For overall issues, go
to `GitHub <https://github.com/barseghyanartur/safezip/issues>`_.

Author
======

Artur Barseghyan <artur.barseghyan@gmail.com>
