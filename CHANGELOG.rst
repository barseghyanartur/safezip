Release history and notes
=========================
.. Internal references

.. _Armenian genocide: https://en.wikipedia.org/wiki/Armenian_genocide

`Sequence based identifiers
<http://en.wikipedia.org/wiki/Software_versioning#Sequence-based_identifiers>`_
are used for versioning (schema follows below):

.. code-block:: text

    major.minor[.revision]

- It is always safe to upgrade within the same minor version (for example,
  from 0.3 to 0.3.4).
- Minor version changes might be backwards incompatible. Read the
  release notes carefully before upgrading (for example, when upgrading from
  0.3.4 to 0.4).
- All backwards incompatible changes are mentioned in this document.

0.2.1
-----
2026-10-16

- **Security:** ``max_files`` is now enforced before ``zipfile`` parses the
  archive (`_guard.py`, `precheck_entry_count`).

  - ``zipfile.ZipFile`` reads the whole central directory and builds a
    ``ZipInfo`` per entry when it is constructed, so the entry-count check
    ran only after that memory was spent, and the cost grows with the size
    of the directory. Rejecting a 15 000-entry archive now peaks at about
    70 KB of Python allocations, against about 9 MB for ``zipfile`` to parse
    the same directory.

  - The Guard now walks the central directory headers in place, with
    constant memory, before ``zipfile`` is called. Like ``zipfile``, it
    follows the directory's byte size and ignores the entry count declared
    in the EOCD record, handles prepended data and both ZIP64 directory
    offsets used by different CPython releases. The count after parsing is
    kept.

- **Security:** Staging files are created exclusively (`_streamer.py`).

  - The temporary file was opened with ``open(path, "wb")``, which follows
    a symlink already present at that name. A local user with write access
    to the destination who won the race for the name could make the
    extractor write through the link.

  - The file is now created with ``O_CREAT | O_EXCL``, so extraction fails
    with ``FileExistsError`` and the existing entry is left untouched.
    Extracted file permissions are unchanged (``0o666`` minus the umask).

- **Security:** ``SAFEZIP_MAX_PER_MEMBER_RATIO=nan`` or
  ``SAFEZIP_MAX_TOTAL_RATIO=nan`` no longer disables the Streamer's ratio
  checks (`_core.py`). ``nan``, ``inf``, zero and negative ratio values are
  ignored with a warning and the default applies. Unparsable integer
  values are now logged as well.

- **Backwards incompatible:** ``SAFEZIP_MAX_*_RATIO=0`` or a negative value
  used to reject every non-empty member; it is now ignored and the default
  ratio applies. A raced staging file name raises ``FileExistsError``
  instead of being overwritten.

- **Documentation:**

  - Corrected `ARCHITECTURE.rst`: in-memory archives are spilled to a
    temporary file and receive overlap detection; they do not skip it.
  - `SECURITY.rst` lists 0.2.x as supported.
  - README documents the CLI and ``SAFEZIP_RECURSIVE``; AGENTS.md describes
    ``recursive=True``.
  - `docs/full_llms.rst` no longer includes itself, and local tooling
    directories are excluded from the generated source tree. Added
    ``make source-tree``.

- **Tests:** Regression fixtures and tests for the entry-count pre-check
  (understated EOCD count, prepended data, ZIP64, in-memory input, peak
  memory of a rejection), a planted staging symlink, dangling symlink or
  regular file (plain and recursive extraction), and invalid ratio
  environment values. Security abort tests assert that no partial files
  remain.

- **Repository:** Removed ``path/to/file.zip`` and ``path/to/archive.zip``,
  documentation-test output that had been committed by accident. tox and CI
  create ``path/to`` themselves.

0.2
---
2026-10-16

- **Security:** Fixed a ZipSlip bypass in recursive extraction
  (``recursive=True`` / ``--recursive``) in `_core.py`.

  - On Python 3.10–3.13, ``Path("...zip").stem`` is ``..``, so a nested
    archive member named ``...zip`` (or ``...jar``, ``...whl``, etc.) made
    the nested extraction root resolve to the parent of the destination
    directory. Each nesting level could climb one directory further, allowing
    arbitrary file writes and overwrites outside the extraction root.
    Python 3.14 was not affected.

  - `_archive_stem` no longer returns ``""``, ``.`` or ``..``; such names
    are kept unchanged.

  - The nested extraction root is now re-validated by the Sandbox
    (`resolve_member_path`). An escaping root raises ``UnsafeZipError`` and
    emits a ``zip_slip_detected`` security event.

- **Backwards incompatible:** With ``recursive=True`` on Python 3.10–3.13,
  nested archives named ``..zip`` or ``...zip`` are now extracted into a
  directory with that exact name (matching Python 3.14 behaviour), instead
  of the current or parent directory.

- **Tests:** Added a regression fixture (`nested_dotdot_stem_archive`) and
  tests for `_archive_stem`, the escape attempt, and the Sandbox
  defence-in-depth check (exception, event emission, no partial files).

0.1.7
-----
2026-06-08

- **Security:** Fixed multiple ZipSlip bypass vulnerabilities in `_sandbox.py`.

  - Fixed bypass via Windows drive-prefix stripping: Filenames like
    ``C:../etc/target`` would have the drive prefix stripped AFTER the
    traversal check, allowing ``..`` components to escape the sandbox.

  - Fixed symlink-based containment bypass: Path resolution now uses
    ``.resolve()`` on both the target path and base directory to prevent
    symlinks from escaping the extraction boundary.

- **Tests:** Added comprehensive test coverage for drive-prefix bypass
  variants and symlink chain escapes.

0.1.6
-----
2026-03-17

- **Comprehensive zip bomb detection**: Replaced `ZipInspector` with full
  Fifield 2019 detection (overlap, extra-field quoting, per-file/aggregate
  ratio, Zip64, bzip2). Configurable thresholds.
- **Content-based nested archive detection**: Uses `zipfile.is_zipfile()`
  instead of extension-only checks; prevents extension-spoofing attacks.
- **Permission sanitisation**: New `strip_special_bits` option strips
  setuid/setgid/sticky bits from extracted files (default: True).
- **Module-level env-var caching**: Default limits cached at import time for
  performance, with runtime env-var overrides still supported.
- **Event improvements**: Added `nesting_depth_exceeded` event type.
- **Type safety**: Added explicit `TypeError` for `None` path in `extract()`.
- **Documentation**: Updated ARCHITECTURE.rst with new features.


0.1.5
-----
2026-03-17

- **Fifield-style zip bomb detection**: Added `ZipInspector` class to detect
  overlapping local entries in zip archives, preventing sophisticated
  compression-ratio attacks.

0.1.4
-----
2026-03-03

- **Recursive extraction**:
  `SafeZipFile(..., recursive=True, max_nesting_depth=3)` (and `safe_extract`)
  auto-descends into nested `.zip` files, extracting them into subdirectories.
  All safety limits apply at every level.
- **CLI**: New `safezip` command (`extract` + `list` subcommands) with full
  support for all security limits, passwords, symlink policies, and
  recursive mode.
- **Nesting protection**: `max_nesting_depth` guard + `NestingDepthError`
  prevents deep zip-bomb recursion.
- **Docs & tests**: Updated README.rst/AGENTS.md with examples,
  added `ARCHITECTURE.rst`, complete CLI + recursive integration test suites.
- **Misc**: Simplified `Makefile`, `.gitignore` cleanup.

0.1.3
-----
2026-03-01

- Minor fixes in docs and tests.

0.1.2
-----
2026-02-28

- Minor fixes.

0.1.1
-----
2026-02-27

- Tested against Python 3.15.

0.1
-----
2026-02-25

- Initial beta release.
