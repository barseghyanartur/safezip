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
