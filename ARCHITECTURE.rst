============================================
safezip — Hardened ZIP Extraction for Python
============================================

:Author: Artur Barseghyan
:Status: Active
:Date: 2026-02-25
:Version: 0.1.6

.. contents:: Table of Contents
   :depth: 3
   :backlinks: none

----

Core Philosophy
===============

**Secure by Default**
    Every defence is active with no configuration required. The user must take
    a deliberate, documented action to relax any limit.

**Composition, Not Inheritance**
    ``SafeZipFile`` wraps ``zipfile.ZipFile`` internally. No unsafe method from
    the standard library is reachable through the public API.

**Streaming is the Authoritative Defence**
    The Guard phase is a cheap pre-filter for early rejection. Runtime
    enforcement — actual decompressed byte counts, path safety — is verified
    during streaming. The per-member file-size limit is applied in both phases:
    in the Guard against the declared header value (cheap early rejection), and
    in the Streamer against observed decompressed bytes (authoritative).
    Compression-ratio checks use the header-reported compressed size as the
    denominator; the numerator is always the actual decompressed byte count.

**Explicit Over Implicit**
    No silent defaults for destructive parameters. An extraction path must
    always be provided explicitly.

**Zero Dependencies**
    The package depends only on the Python standard library. Security-sensitive
    infrastructure should not pull in a transitive dependency graph.

**Opt-In Telemetry**
    Monitoring hooks are disabled by default and emit only sanitised,
    data-minimised events.

----

Package Architecture
====================

Phase A — The Guard (Pre-Extraction Filter)
-------------------------------------------

Role
~~~~

Perform cheap static analysis on the Central Directory to reject obviously
malformed or suspicious archives *before* any decompression begins. This is a
best-effort filter, not a trusted security boundary.

Checks
~~~~~~

**Sanity bounds (trusted)**
    Verify ``len(infolist())`` against ``max_files``. Reject immediately if
    exceeded. This check is reliable because it does not depend on
    decompressed data.

**ZIP64 consistency check**
    Two sub-cases are checked:

    - If a 32-bit size field holds the sentinel value ``0xFFFFFFFF`` (meaning
      "see the ZIP64 extra field") but no ZIP64 extra field is present, the
      archive is structurally malformed and rejected immediately.
    - If a ZIP64 extra field is present and its reported size *differs* from
      the size that Python's ``zipfile`` resolved from the central directory,
      the archive has been tampered with and is rejected.  The discrepancy can
      appear in either direction (ZIP64 larger *or* smaller than 32-bit), so
      any mismatch is treated as suspicious.

**Filename null-byte check (pre-streaming)**
    Reject filenames containing null bytes before streaming begins.  Broader
    character-level path-safety checks (absolute paths, traversal, OS path
    limits) are enforced by the Sandbox during extraction.

**Structural validity (delegated to Python's zipfile)**
    Python's ``zipfile.ZipFile`` validates the End-of-Central-Directory entry
    count against the number of actually parsed entries at archive open time.
    Any mismatch causes ``zipfile.BadZipFile``, which ``SafeZipFile`` wraps as
    ``MalformedArchiveError`` before the Guard runs.

Partially trusted in the Guard
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- **Reported file sizes**: used for early rejection (if a declared size already
  exceeds ``max_file_size``, the archive is rejected before decompression).
  The Streamer enforces the same limit against actual decompressed bytes.
- **Compression ratios reported in headers**: not used.  Ratio checks in the
  Streamer use the header-reported *compressed* size as the denominator but
  the actual *decompressed* byte count as the numerator.
- **Overlap detection based on offsets**: implemented. The Guard parses the
  central directory and each entry's local header to compute the byte span
  occupied by every entry. If any two spans overlap, the archive is rejected
  as a likely Fifield-style zip bomb before any decompression begins. This
  check uses the ``detect_zip_bomb()`` function in ``_guard.py``, which
  implements full Fifield 2019 detection including: full-overlap,
  quoted-overlap (giant-steps), extra-field quoting, Zip64 extensions,
  bzip2 variants, and per-file/aggregate compression ratio limits.
  Detection emits the ``malformed_archive`` security event. No configuration
  options are exposed for this check — it is always enabled when the archive
  is opened.

  .. note::

     The overlap detection requires a filesystem-backed path (the file must have
     a ``name`` attribute). For in-memory ``BinaryIO`` objects without a path,
     the check is skipped and a warning is logged. Users extracting untrusted
     archives from memory should write to a temporary file first.

Phase B — The Sandbox (Path Manager)
------------------------------------

Role
~~~~

Resolve every candidate extraction path against a strictly enforced base
directory. All filesystem interaction is mediated through this class.

Path normalisation pipeline
~~~~~~~~~~~~~~~~~~~~~~~~~~~

For each member filename, the following transformations and checks are applied
in order:

1. **Receive a decoded string.** Python's ``zipfile`` decodes the raw filename
   bytes before passing them to the Sandbox.  The Sandbox operates on a Python
   ``str``, not raw bytes.
2. Apply Unicode NFC normalisation to canonicalise combining-character
   sequences (e.g., NFD ``e + ́`` → NFC ``é``).
3. Reject filenames containing null bytes.
4. Reject any leading ``/``, ``\``, or Windows drive letter
   (``C:\``, ``//server/share``).
5. Reject ``..`` path components explicitly.  The resolved path is also
   verified to remain under the base directory.
6. Reject filenames whose resolved absolute length exceeds a conservative
   ``MAX_PATH`` cap (4 096 characters).

Symlink policy
~~~~~~~~~~~~~~

Controlled by the ``symlink_policy`` constructor parameter:

``SYMLINK_REJECT`` *(default)*
    Any member that is a symlink causes ``UnsafeZipError`` to be raised.

``SYMLINK_IGNORE``
    Symlink members are silently skipped. The archive is otherwise extracted.

``SYMLINK_RESOLVE_INTERNAL``
    ZIP symlink entries store the link target path as the entry's file content.
    ``safezip`` writes this content as a **regular file** — no OS symlink is
    created on disk.  The extracted file contains the raw link-target string
    (e.g. ``../escape.txt``), which is harmless as plain text.

    A post-extraction chain-verification pass (``check_symlink`` /
    ``_verify_symlink_chain`` in ``_sandbox.py``) exists as a defence-in-depth
    measure.  It fires only when the OS *actually* materialises a symlink at
    the destination path.  Because Python's ``zipfile`` does not create OS
    symlinks when extracting ZIP symlink entries, this pass is not triggered by
    the current implementation; it is reserved for any future code path or
    platform-specific writer that might do so.

Atomic write contract
~~~~~~~~~~~~~~~~~~~~~

Each member is written to ``{destination}.safezip_tmp_{pid}_{random}`` and
renamed to the final destination only after the Streamer confirms the member
passed all checks. If an exception is raised at any point, the temporary file
is deleted.

Phase C — The Streamer (Runtime Enforcement)
--------------------------------------------

Role
~~~~

Perform byte-level monitoring during actual decompression. This is the
authoritative security boundary.

Per-member stream monitors
~~~~~~~~~~~~~~~~~~~~~~~~~~

**Real-size monitor**
    Maintain a running byte count. If ``bytes_written > max_file_size``, raise
    ``FileSizeExceededError`` and delete the in-progress temporary file.

**Per-member ratio monitor**
    After each read chunk, compute
    ``member_bytes_decompressed / member_compressed_size``.
    If the ratio exceeds ``max_per_member_ratio``, raise
    ``CompressionRatioError`` immediately and delete the in-progress temporary
    file.  The numerator (``member_bytes_decompressed``) is the running count
    of actual bytes written.  The denominator (``member_compressed_size``) is
    taken from the ``compress_size`` field that Python's ``zipfile`` populates
    from the central directory, which is always correct for non-empty members
    of any well-formed archive.

    The check is skipped when ``compress_size == 0``.  The only reachable case
    for this condition is a genuinely empty member, where skipping is correct
    (there is nothing to decompress).  A malformed archive that carries
    ``compress_size=0`` in the central directory for a non-empty member causes
    Python's ``zipfile`` to read zero bytes and then fail its own CRC
    verification with ``BadZipFile``, so ``safezip``'s ratio logic is never
    reached in that case.

**Total ratio monitor**
    After each chunk, also compute
    ``total_bytes_decompressed / estimated_total_compressed`` across *all*
    members extracted so far in the current call.  If this exceeds
    ``max_total_ratio``, raise ``CompressionRatioError``.  This catches
    distributed ZIP bombs where each individual member stays below
    ``max_per_member_ratio`` but the archive as a whole inflates to a dangerous
    total size.  The denominator is an estimate derived from header values.

**Cumulative size monitor**
    Track total bytes written across all members in the current extraction
    call. If ``total_bytes_written > max_total_size``,
    raise ``TotalSizeExceededError``.

Nesting depth guard
~~~~~~~~~~~~~~~~~~~

By default (``recursive=False``) ``SafeZipFile`` treats nested archives as
opaque blobs: members whose filename ends with ``.zip``, ``.jar``, ``.war``,
``.ear``, or any other extension in the hardcoded ``_ARCHIVE_EXTENSIONS`` set
are streamed to disk as raw files. No inner content is decompressed.

When ``recursive=True``, ``SafeZipFile`` performs **content-based detection**:
the nested archive is first streamed to a temporary file, then checked using
``zipfile.is_zipfile()`` to determine if it's actually a ZIP. This prevents
attackers from bypassing security by using misleading extensions (e.g., a file
named ``data.csv`` that is actually a ZIP archive).

When ``recursive=True``, ``SafeZipFile`` descends into each nested archive
automatically:

1. The nested archive is first streamed to a temporary file using the same
   Streamer phase as any other member, so all per-member and cumulative limits
   apply to the zip file itself.
2. A child ``SafeZipFile`` is opened on the temp file with
   ``_nesting_depth + 1`` and all limits inherited from the parent
   (``max_file_size``, ``max_total_size``, ``max_files``,
   ``max_per_member_ratio``, ``max_total_ratio``, ``max_nesting_depth``,
   ``symlink_policy``, ``password``, ``on_security_event``).
3. The child runs its own full Guard → Sandbox → Streamer pipeline on the
   inner archive's members.
4. Contents are extracted into a directory named after the archive member
   without its extension (``inner.zip`` → ``inner/``). The ``.zip`` file
   itself is never written to disk.
5. The temporary file is deleted in a ``finally`` block regardless of outcome.

Each recursion level has independent ``CumulativeCounters``; limits are not
shared across levels. If ``_nesting_depth`` exceeds ``max_nesting_depth``
(default: ``3``) when the child is instantiated, ``NestingDepthError`` is
raised before any inner decompression begins.

----

Public API
==========

``SafeZipFile``
---------------

.. code-block:: python
    :name: safe_zipfile

        class SafeZipFile:
        def __init__(
            self,
            file,
            mode="r",
            *,
            # All Optional[...] = None; defaults are resolved from env vars
            # then fall back to the hardcoded values shown in comments.
            max_file_size: Optional[int] = None,       # default: 1 GiB
            max_total_size: Optional[int] = None,      # default: 5 GiB
            max_files: Optional[int] = None,           # default: 10 000
            max_per_member_ratio: Optional[float] = None,  # default: 200.0
            max_total_ratio: Optional[float] = None,   # default: 200.0
            max_nesting_depth: Optional[int] = None,   # default: 3
            symlink_policy: Optional[SymlinkPolicy] = None,  # default: REJECT
            password: Optional[bytes] = None,
            on_security_event: Optional[Callable[[SecurityEvent], None]] = None,
            recursive: bool = False,
            strip_special_bits: bool = True,
        ): ...

        def extract(
            self,
            member: str | ZipInfo,
            path: str | os.PathLike,             # required; no default
            *,
            pwd: bytes | None = None,
        ) -> str: ...

        def extractall(
            self,
            path: str | os.PathLike,             # required; no default
            members: list[str | ZipInfo] | None = None,
            *,
            pwd: bytes | None = None,
        ) -> None: ...

        def namelist(self) -> list[str]: ...
        def infolist(self) -> list[ZipInfo]: ...
        def getinfo(self, name: str) -> ZipInfo: ...

        # Context manager support
        def __enter__(self) -> "SafeZipFile": ...
        def __exit__(self, *args) -> None: ...

Intentionally omitted methods
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following ``zipfile.ZipFile`` methods are **not** exposed:

- ``open()`` — returns a raw file-like object, bypassing stream monitors.
- ``read()`` — reads a full member into memory without size enforcement.
- ``_extract_member()`` — internal implementation method, not public.
- ``write()`` / ``writestr()`` — write-mode operations are out of scope.

If a caller needs lower-level access, they use ``zipfile.ZipFile`` directly,
accepting the associated risks.

``safe_extract`` convenience function
-------------------------------------

A module-level convenience function for the common single-call use case:

.. code-block:: python

    def safe_extract(
        archive: str | os.PathLike | BinaryIO,
        destination: str | os.PathLike,
        **kwargs,           # forwarded to SafeZipFile constructor
    ) -> None:
        """Extract archive to destination using SafeZipFile defaults."""

----

Configuration via Environment Variables
=======================================

In containerised deployments, constructor arguments may not be accessible. All
limits (numeric and policy) accept overrides from environment variables, with
the constructor argument taking precedence:

+----------------------------------------+------------------------------------+
| Environment variable                   | Corresponding parameter            |
+========================================+====================================+
| ``SAFEZIP_MAX_FILE_SIZE``              | ``max_file_size``                  |
+----------------------------------------+------------------------------------+
| ``SAFEZIP_MAX_TOTAL_SIZE``             | ``max_total_size``                 |
+----------------------------------------+------------------------------------+
| ``SAFEZIP_MAX_FILES``                  | ``max_files``                      |
+----------------------------------------+------------------------------------+
| ``SAFEZIP_MAX_PER_MEMBER_RATIO``       | ``max_per_member_ratio``           |
+----------------------------------------+------------------------------------+
| ``SAFEZIP_MAX_TOTAL_RATIO``            | ``max_total_ratio``                |
+----------------------------------------+------------------------------------+
| ``SAFEZIP_MAX_NESTING_DEPTH``          | ``max_nesting_depth``              |
+----------------------------------------+------------------------------------+
| ``SAFEZIP_SYMLINK_POLICY``             | ``symlink_policy``                 |
+----------------------------------------+------------------------------------+
| ``SAFEZIP_RECURSIVE``                  | ``recursive``                      |
+----------------------------------------+------------------------------------+
| ``SAFEZIP_MAX_TOTAL_SIZE``             | ``max_total_size``                 |
+----------------------------------------+------------------------------------+
| ``SAFEZIP_MAX_FILES``                  | ``max_files``                      |
+----------------------------------------+------------------------------------+
| ``SAFEZIP_MAX_PER_MEMBER_RATIO``       | ``max_per_member_ratio``           |
+----------------------------------------+------------------------------------+
| ``SAFEZIP_MAX_TOTAL_RATIO``            | ``max_total_ratio``                |
+----------------------------------------+------------------------------------+
| ``SAFEZIP_MAX_NESTING_DEPTH``          | ``max_nesting_depth``              |
+----------------------------------------+------------------------------------+
| ``SAFEZIP_SYMLINK_POLICY``             | ``symlink_policy``                 |
+----------------------------------------+------------------------------------+

----

Exception Hierarchy
===================

All exceptions inherit from ``SafezipError`` so callers can catch the package's
entire error surface with a single ``except`` clause:

.. code-block:: text

    SafezipError (base)
    ├── UnsafeZipError         # path traversal, absolute paths, symlinks
    ├── FileSizeExceededError  # single member exceeds max_file_size
    ├── TotalSizeExceededError # cumulative extraction exceeds max_total_size
    ├── CompressionRatioError  # decompression ratio exceeds max_ratio
    ├── FileCountExceededError # member count exceeds max_files
    ├── NestingDepthError      # nested archive depth exceeds max_nesting_depth
    └── MalformedArchiveError  # ZIP64 overflow, entry count mismatch, etc.

----

Logging Strategy
================

``safezip`` uses Python's standard ``logging`` module, channel name
``safezip.security``. This integrates with any existing application log stack
without requiring a third-party service.

.. code-block:: python
    :name: logging_example

    import logging
    log = logging.getLogger("safezip.security")

    # Example emission on path traversal detection:
    log.warning(
        "Path traversal attempt blocked",
        extra={
            "event": "zip_slip_detected",
            "member": member_name[:256],   # truncated; no resolved path
            "archive_hash": sha256_prefix, # first 16 hex chars only
        },
    )

All ``extra`` fields are length-capped. Resolved filesystem paths are never
emitted to avoid leaking confidential directory structures.

Optional structured JSON emission is available by attaching Python's
``logging.handlers.MemoryHandler`` or any JSON formatter — no custom code
required inside ``safezip``.

``on_security_event`` callback
------------------------------

An optional callback that receives a ``SecurityEvent`` object every
time ``safezip`` detects a security event (path traversal, ratio violation,
malformed archive, etc.). The callback can forward the event to any monitoring
system the application already uses (Sentry, Datadog, OpenTelemetry, a log
file, an email alert, etc.).

By default the parameter is ``None`` and nothing happens.

.. code-block:: python
    :name: callback_example

    import sentry_sdk
    from safezip import SafeZipFile, SecurityEvent

    def forward_to_sentry(event: SecurityEvent) -> None:
        # event contains: event_type, archive_hash, timestamp
        # It never contains filenames or paths (privacy protection).
        sentry_sdk.capture_message(
            f"safezip: {event.event_type}",
            level="warning",
            extras={"archive_hash": event.archive_hash},
        )

    with SafeZipFile("upload.zip", on_security_event=forward_to_sentry) as zf:
        zf.extractall("/var/uploads/extracted/")

If ``upload.zip`` contains a path traversal attempt, ``forward_to_sentry``
is called automatically. Extraction is still blocked; the callback is
informational only — it cannot override security decisions.

``SecurityEvent`` fields
~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python
    :name: security_event_fields

    @dataclass
    class SecurityEvent:
        event_type: str       # see table below
        archive_hash: str     # first 16 hex chars of SHA-256 of the archive path/name
        timestamp: float      # time.time() at the moment of detection

Filenames, paths, and member names are deliberately excluded so that forwarding
an event to a third-party service does not leak confidential filesystem
information.

Emitted ``event_type`` values:

+------------------------------+----------------------------------------------+
| ``event_type``               | Trigger                                      |
+==============================+==============================================+
| ``zip_slip_detected``        | Path traversal or absolute path blocked      |
+------------------------------+----------------------------------------------+
| ``symlink_rejected``         | Symlink entry with ``REJECT`` policy         |
+------------------------------+----------------------------------------------+
| ``symlink_ignored``          | Symlink entry with ``IGNORE`` policy         |
+------------------------------+----------------------------------------------+
| ``file_size_exceeded``       | Per-member size limit hit during streaming   |
+------------------------------+----------------------------------------------+
| ``total_size_exceeded``      | Cumulative size limit hit during streaming   |
+------------------------------+----------------------------------------------+
| ``compression_ratio_exceeded`` | Ratio limit hit during streaming           |
+------------------------------+----------------------------------------------+
| ``file_count_exceeded``      | Entry count limit hit in Guard phase         |
+------------------------------+----------------------------------------------+
| ``declared_size_exceeded``   | Declared header size > limit in Guard phase  |
+------------------------------+----------------------------------------------+
| ``malformed_archive``        | Structural anomaly detected in Guard phase   |
+------------------------------+----------------------------------------------+
| ``nesting_depth_exceeded``   | Nested archive depth exceeds limit           |
+------------------------------+----------------------------------------------+

Callback error handling
~~~~~~~~~~~~~~~~~~~~~~~

If the callback itself raises an exception, ``safezip`` logs the traceback
to ``safezip.security`` at ``ERROR`` level, then continues with security
enforcement as normal. The callback failure never suppresses the
underlying ``SafezipError``.

----

Defaults Rationale
==================

.. list-table::
   :header-rows: 1
   :widths: 22 12 66

   * - Parameter
     - Default
     - Rationale
   * - ``max_file_size``
     - 1 GiB
     - Large enough for virtually all legitimate single-file payloads; prevents
       runaway decompression from a single malicious entry.
   * - ``max_total_size``
     - 5 GiB
     - Conservative upper bound for archive payloads in typical server
       workloads. Should be raised by users processing media archives.
   * - ``max_files``
     - 10 000
     - Exceeding this count is unusual for legitimate uploads; very common in
       zip-of-small-files bomb variants.
   * - ``max_per_member_ratio``
     - 200
     - Legitimate high-compression data (log files, sparse matrices) rarely
       exceeds 100:1. 200 provides a safety margin while blocking the ~10 000:1
       ratios typical of single-member ZIP bombs.
   * - ``max_total_ratio``
     - 200
     - Applies the same 200:1 limit to the archive as a whole. This catches
       distributed bombs where many individually innocent members together
       inflate to a dangerous total size. Matching the per-member default is
       deliberate: a legitimate archive of legitimately-compressible files
       should not systematically exceed what any single member is allowed.
   * - ``max_nesting_depth``
     - 3
     - Deeply nested archives have no legitimate everyday use case. Three
       levels of nesting (zip→zip→zip) is already unusual.
   * - ``symlink_policy``
     - REJECT
     - Symlinks in untrusted archives are almost always malicious. Users who
       need symlinks should opt in explicitly.
   * - ``strip_special_bits``
     - True
     - Strip setuid, setgid, and sticky bits from extracted files. Protects
       against archives that try to preserve executable permissions on malicious
       scripts.

----

Testing Strategy
================

Principle: No Mocks, No Stubs
-----------------------------

All security tests use real, crafted malicious archive files. Test archives are
generated programmatically in a ``conftest.py`` fixture using
Python's ``struct`` module and ``zipfile`` (for the non-malicious parts). This
makes the test suite self-contained, cross-platform, and independent of system
tools.

Test cases
----------

ZipSlip — relative path traversal
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python
    :name: zip_slip_relative

    # Craft an entry named "../../tmp/evil.txt" at the raw byte level.
    # Use struct.pack to write the Local File Header with the crafted name.
    # Expected: UnsafeZipError raised before any bytes reach the filesystem.

ZipSlip — absolute path
~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python
    :name: zip_slip_absolute

    # Entry named "/etc/passwd" (Unix) and "C:\\Windows\\cmd.exe" (Windows).
    # Expected: UnsafeZipError.

ZipSlip — Unicode normalisation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python
    :name: zip_slip_unicode

    # Entry filename contains combining Unicode characters (NFD form) that
    # NFC-normalise to a precomposed character but still include a ".."
    # traversal component: e.g. "e\u0301vil/../../escape.txt" normalises to
    # "évil/../../escape.txt".  The ".." is unaffected by NFC and must still
    # be detected and rejected.
    # Expected: UnsafeZipError.

ZIP bomb — high compression ratio
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python
    :name: zip_bomb_compression_ratio

    # Compress a 10 MiB file of null bytes (ratio ≈ 7 000:1 after zlib).
    # Set max_ratio=50 in the constructor.
    # Expected: CompressionRatioError before extraction completes.

ZIP bomb — header size lie
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python
    :name: zip_bomb_header_size_lie

    # Craft a ZIP entry that reports compressed_size=1000,
    # uncompressed_size=500 but whose decompressed content is actually 2 GiB.
    # Set max_file_size=100 * 1024 * 1024 (100 MiB).
    # Expected: FileSizeExceededError. Confirm no partial file remains on disk.

ZIP bomb — many small files
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python
    :name: zip_bomb_many_files

    # Archive with 10 001 valid but tiny entries.
    # Expected: FileCountExceededError raised during Guard phase.

Symlink rejection
~~~~~~~~~~~~~~~~~

.. code-block:: python
    :name: symlink_rejection

    # Archive with a symlink entry pointing to /etc/passwd.
    # Expected: UnsafeZipError with SYMLINK_REJECT (default).
    # With SYMLINK_IGNORE: entry is skipped, no error.
    # With SYMLINK_RESOLVE_INTERNAL: regular files are extracted normally.

Nested archive depth limit
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python
    :name: nested_archive_depth

    # Use recursive=True on a 3-level archive with max_nesting_depth=1.
    # SafeZipFile opens level 0 (OK), then level 1 (OK), then tries to open
    # level 2 and raises NestingDepthError before any inner decompression.
    # Expected: NestingDepthError.
    # A depth equal to max_nesting_depth is permitted (depth=1 with limit=1
    # is allowed; depth=2 is not).

ZIP64 overflow
~~~~~~~~~~~~~~

.. code-block:: python
    :name: zip64_overflow

    # Craft a ZIP64 extra field where the size value wraps around to near-zero.
    # Expected: MalformedArchiveError during Guard phase.

Null byte in filename
~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python
    :name: null_byte_filename

    # Entry filename: b"safe_name\x00../../etc/passwd"
    # Python's zipfile truncates at the null byte; verify the truncated name
    # contains no traversal components and extraction proceeds safely.

Atomic write — cleanup on failure
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python
    :name: atomic_write_cleanup

    # Trigger FileSizeExceededError mid-stream on a large entry.
    # After the exception, verify the destination directory contains no partial
    # files (no .safezip_tmp_* files remain).

Explicit path requirement
~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python
    :name: explicit_path_required

    # Call safe_zf.extractall()  # no path argument
    # Expected: TypeError, not silent extraction to CWD.

----

Distribution and Packaging
==========================

- **Python version:** 3.10+.  The code uses ``typing.Optional`` /
  ``typing.Union`` for compatibility; ``if``/``elif`` chains are used for
  policy dispatch rather than ``match``/``case``.  3.10 is the minimum
  declared in ``pyproject.toml`` for broad ecosystem compatibility.
- **Dependencies:** None. Standard library only.
- **Packaging:** ``pyproject.toml`` with ``[build-system]`` using
  ``setuptools``.
- **Type annotations:** Full ``py.typed`` marker included.
- **Licence:** MIT.

Directory layout
-----------------

.. code-block:: text

    safezip/
    ├── pyproject.toml
    ├── ARCHITECTURE.rst            ← this document
    ├── src/
    │   └── safezip/
    │       ├── __init__.py      # public re-exports only
    │       ├── _core.py         # SafeZipFile implementation
    │       ├── _guard.py        # Phase A: pre-extraction validation
    │       ├── _sandbox.py      # Phase B: path management
    │       ├── _streamer.py     # Phase C: streaming extraction
    │       ├── _exceptions.py   # exception hierarchy
    │       ├── _events.py       # SecurityEvent dataclass + SymlinkPolicy enum
    │       └── py.typed
    └── tests/
        ├── conftest.py          # archive factory fixtures
        ├── test_guard.py
        ├── test_sandbox.py
        ├── test_streamer.py
        ├── test_integration.py  # end-to-end with real malicious archives
        └── archives/            # generated by conftest; gitignored

----

Background: ZIP64 and Integer Overflow
======================================

What is ZIP64?
--------------

The original ZIP format was designed in 1989. File sizes and archive sizes were
stored as 32-bit unsigned integers, which means the maximum value for any
single field was 4 294 967 295 — just under 4 GiB. In 2001, the ZIP64 extension
was introduced to support larger files. ZIP64 stores sizes in 64-bit fields,
raising the limit to roughly 18 exabytes.

ZIP64 fields are written into a variable-length block called an "extra field"
that is attached to each ZIP entry's header alongside the original 32-bit
fields.
Parsers are supposed to check:
*if the 32-bit field contains the sentinel value* ``0xFFFFFFFF``
*(meaning "look in the ZIP64 extra field for the real value"), *
*use the 64-bit value instead.*

How the overflow attack works
-----------------------------

A malicious archive author can craft a ZIP64 extra field containing a very
large 64-bit size value — for example, ``0xFFFFFFFFFFFFFFFF`` (the maximum
possible 64-bit unsigned integer, equal to about 18.4 exabytes). A naive parser
that reads this value and then does arithmetic on it — for instance, adding it
to an offset counter or comparing it with a size limit — may experience
integer overflow.

In Python (which uses arbitrary-precision integers), raw overflow is not
possible, but the danger is different: a malicious ``uncompressed_size`` field
close to ``2^64`` causes a naively written ratio check to misbehave. For
example, if the reported size is ``2^64 - 1`` and the compressed size
is ``1000``, the reported ratio is astronomical and would trigger an
alert — *unless* the parser silently truncates or masks the value to a
smaller type at some point, making the size appear to be near zero. In that
case, size checks see "0 bytes expected" and pass the member through
unchallenged, even though decompressing it produces gigabytes of output.

A subtler variant: set the ZIP64 ``uncompressed_size`` to a value that is just
above the 32-bit maximum (e.g., ``4 294 967 296``). Some parsers read the
32-bit field first (which is set to ``0xFFFFFFFF``) and only fall back to ZIP64
when that sentinel is seen. If the fallback logic has an off-by-one error, the
size may be misread as exactly ``0xFFFFFFFF`` (a legitimate-looking large
number that still passes a 1 GiB check) rather than the true value of several
hundred gigabytes.

Why ``safezip`` catches this in the Guard phase
-----------------------------------------------

Before any decompression begins, the Guard reads every entry's ZIP64 extra
field and applies two consistency rules:

- If a 32-bit size field is set to the sentinel value ``0xFFFFFFFF`` but no
  ZIP64 extra field is present, the entry is structurally malformed. Reject.
- If a ZIP64 extra field is present and its value *differs* (in either
  direction) from the size Python's ``zipfile`` resolved from the central
  directory, the archive has been tampered with. Reject.  This catches both
  the "large ZIP64 hidden behind a small 32-bit value" attack and the reverse.

Additionally, if the declared ``uncompressed_size`` (as resolved by Python)
already exceeds ``max_file_size``, the entry is rejected before decompression
starts. The Streamer enforces the same limit against actual byte counts, making
this an early-rejection optimisation rather than a standalone security
boundary.

These checks are not a substitute for the Streamer's runtime monitoring — they
are an additional layer that catches the most obviously crafted archives before
a single byte is decompressed.

Is this check opt-outable?
--------------------------

**No.** A ZIP64 extra field that is inconsistent with the central directory is
not a valid ZIP file under any interpretation of the specification. It is
always either a file creation bug or deliberate tampering. Forensics users who
need to inspect such archives should use ``zipfile.ZipFile`` directly,
accepting the associated risks.

----

Out of Scope
============

- **Writing ZIP archives.** ``safezip`` is extraction-only.
- **Password-protected archives.** Encrypted ZIPs introduce a timing-based
  oracle attack surface beyond the current scope. Encrypted archive support, if
  added, requires a separate security review.
- **Repairing malformed archives.** If the Guard detects a malformed archive,
  it raises an exception. It does not attempt recovery.
