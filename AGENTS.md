# AGENTS.md

**AI Agent / LLM Instructions for `safezip`**

**Last updated**: 2026-03-01
**Package version**: See pyproject.toml
**Repository**: https://github.com/barseghyanartur/safezip
**Primary maintainer**: Artur Barseghyan <artur.barseghyan@gmail.com>

This file is written specifically for AI coding agents (Claude, Grok, Cursor, Windsurf, Aider, Continue.dev, etc.).
Follow these guidelines when you are asked to **use**, **analyze**, **fix**, **extend**, **review**, **document**, or **integrate** this package in code or responses.

---

## 1. Project Mission (Never Deviate)

> **"Hardened ZIP extraction for Python — secure by default, zero dependencies, production-grade."**

When **using** the package:
- Always emphasize **secure defaults** in examples (e.g., no custom limits unless needed).
- Recommend `safe_extract` for simple cases; `SafeZipFile` for control.

When **developing/extending**:
- Preserve **zero external dependencies** (stdlib only).
- Keep the library **secure by default** (no relaxed limits unless explicitly requested).
- Maintain the **three-phase security model** (Guard → Sandbox → Streamer).
- Respect the **atomic-write contract** (never leave partial files on disk after a security abort).

---

## 2. Core Usage Instructions (For LLM Responses Involving the Package)

When a user asks about **using `safezip`** (e.g., "How do I safely extract a ZIP in Python?"):
1. **Start with secure defaults**: Show examples without custom limits first.
2. **Explain risks mitigated**: Briefly mention ZipSlip, bombs, malformed archives.
3. **Provide code snippets**: Use the quick-start from README.rst.
4. **Advise on customization**: Only if asked; warn about relaxing limits.
5. **Test in responses**: If generating code, suggest testing with crafted archives (e.g., via `zipfile` in-memory).

**Basic Usage Template** (copy this into responses):
```python
from safezip import safe_extract

# Simple: Secure defaults protect against common attacks
safe_extract("user_upload.zip", "/path/to/extract")

# Advanced: With custom limits and monitoring
from safezip import SafeZipFile, SecurityEvent

def monitor(event: SecurityEvent) -> None:
    print(f"Security event: {event.event_type}")

with SafeZipFile(
    "user_upload.zip",
    max_file_size=100 * 1024 * 1024,  # 100 MiB per file
    on_security_event=monitor
) as zf:
    zf.extractall("/path/to/extract")
```
- **Key Considerations**:
  - Always use context manager for `SafeZipFile` to ensure close.
  - For user uploads: Validate archive hash or log events.
  - Env vars: Mention overrides (e.g., `export SAFEZIP_MAX_FILES=5000`).
  - Limitations: Note data-descriptor ZIPs skip ratio checks; symlinks extracted as files (not created).

When integrating into larger code (e.g., web apps):
- Wrap in try/except `SafezipError` subclasses.
- Log security events.
- Never auto-relax limits based on input.

---

## 3. Core Architecture (Memorize for Development/Extension)

The library is deliberately split into **three isolated phases**:

| Phase       | File                  | Responsibility                              | When it runs                  | What it can raise                     |
|-------------|-----------------------|---------------------------------------------|-------------------------------|---------------------------------------|
| **Guard**   | `_guard.py`           | Static pre-checks (count, declared sizes, ZIP64 consistency, malformed) | On `SafeZipFile(...)` open   | `FileCountExceededError`, `FileSizeExceededError`, `MalformedArchiveError` |
| **Sandbox** | `_sandbox.py`         | Path sanitization (ZipSlip, absolute paths, Unicode NFC, null bytes, length) + symlink policy | Before every extraction       | `UnsafeZipError`                      |
| **Streamer**| `_streamer.py`        | Streaming decompression + runtime limits (actual size, ratios, cumulative) + atomic temp file | During `extract()` / `extractall()` | `FileSizeExceededError`, `TotalSizeExceededError`, `CompressionRatioError` |

**Never merge responsibilities** between these files.

**Main public API** (`_core.py`):
- `SafeZipFile` (context manager + drop-in replacement for `zipfile.ZipFile` read-only methods).
- `safe_extract(...)` (convenience: open + extractall + close).

**When extending** (e.g., new feature request):
- Add to the appropriate phase (e.g., new path check → Sandbox).
- Update `_core.py` to forward new params if needed.
- Preserve zero-deps: Use stdlib (e.g., `struct` for ZIP parsing).

---

## 4. Security Principles You Must Enforce

1. **Default limits are sacred**
   - Never lower them in examples or defaults.
   - Use `_env_int()` / `_env_float()` / `_env_symlink_policy()` for overrides.

2. **Data-descriptor ZIPs are a known gap**
   - Ratios are **not enforced** when `compress_size == 0`.
   - If fixing/extending, do it in `stream_extract_member` only — do **not** break atomicity.
   - In responses: Warn users if their use case involves streamed ZIPs.

3. **Symlink policy reality (README is slightly outdated)**
   - `RESOLVE_INTERNAL` currently extracts the target string as a **regular file** (does **not** create an OS symlink or verify chains).
   - `check_symlink()` only runs on actual filesystem symlinks.
   - If extending to create real symlinks: Implement in `_extract_one`, use `os.symlink`, verify with `_verify_symlink_chain`, update README/tests.

4. **Atomicity is non-negotiable**
   - Every member → temp file → `replace()` on success.
   - On any exception → `unlink(missing_ok=True)` the temp file.
   - In new code: Follow this pattern.

5. **When using in code**:
   - Assume untrusted inputs; always use full limits.
   - For nested ZIPs: Manually recurse with increased `_nesting_depth` if needed, but warn about bombs.

---

## 5. Coding Conventions and Styles (Based on pyproject.toml)

Follow these strictly when generating or modifying code. They are enforced by tools like ruff, mypy, and doc8.

1. **Line Length**: 88 characters max (ruff setting). Use black-style formatting implicitly.
2. **Linting (ruff)**:
   - Selected rules: B (bugbear), C4 (comprehensions), E (pycodestyle errors), F (pyflakes), G (logging), I (isort), ISC (implicit str concat), INP (no pep420), N (pep8-naming), PERF (performance), Q (flake8-quotes), SIM (simplify).
   - Ignored: G004 (logging-f-string), ISC003 (multi-line concat).
   - Fix mode: Enabled (ruff --fix).
   - Isort: known-first-party = ["safezip"].
   - Dummy variables: Allow underscore-prefixed (e.g., _var).
   - Target: Python 3.10+.
   - Per-file ignores: e.g., "conftest.py" ignores PERF203.
3. **Type Checking (mypy)**:
   - check_untyped_defs = true (check untyped functions).
   - warn_unused_ignores, warn_redundant_casts, warn_unused_configs = true.
   - ignore_missing_imports = true (for stdlib/zero-deps).
4. **Documentation (doc8 + sphinx)**:
   - RST style: Follow hierarchy in README (===== > ===== > ----- > ~~~~~ etc.).
   - Ignore paths: docs/requirements.txt, egg-info/SOURCES.txt.
   - Sphinx: Use rtd-theme, autobuild, no-pragma, markdown-builder, llms-txt-link, source-tree.
5. **Testing (pytest)**:
   - Addopts: -ra -vvv -q --cov=safezip --cov-report=html/term --capture=no.
   - Paths: src/safezip/tests, .rst/.md files.
   - Coverage: ≥95%, show_missing=true, exclude pragma: no cover, @overload.
6. **General Styles**:
   - Imports: Sorted (ruff I), first-party "safezip".
   - Strings: Prefer f-strings, but respect Q (quotes).
   - Naming: pep8 (ruff N).
   - Performance: Avoid loops with try-except (PERF203 ignored in conftest).
   - No additional deps: Enforce in code/reviews.

When editing code: Run `make ruff`, `make doc8`, `mypy`. Pre-commit hooks enforce this.

---

## 6. How to Add / Change Features or Fix Bugs (Agent Workflow)

When a user asks for a **new feature** (e.g., "Add recursive nested ZIP extraction") or **bug fix**:
1. **Quote this section**: Start your response by referencing AGENTS.md workflow.
2. **Analyze impact**: Check against mission (secure? zero-deps?).
3. **Propose code changes**: In the right phase/file, following coding styles (e.g., 88-char lines).
4. **Update tests**: Add to `test_*.py`; craft archives in `conftest.py`.
5. **Test considerations**:
   - Run in Docker: `make docker-test`.
   - Verify atomicity: Assert no partial files post-abort.
   - Cover edges: Data descriptors, ZIP64, Unicode, symlinks.
   - Regression: Reproduce bug first, then fix.
6. **Update docs**: README.rst (examples, limits, limitations).
7. **Security events**: Add emission if new violation type.

**Workflow Template**:
```text
1. Reproduce issue with a new fixture in conftest.py.
2. Fix in [phase file, e.g., _streamer.py].
3. Add unit test in test_[phase].py.
4. Add integration test in test_integration.py (verify no partials).
5. Update README.rst if API/docs change.
6. Suggest running: make docker-test.
```

**Acceptable new features**:
- Data-descriptor ratio tracking (track compressed bytes during stream).
- Optional recursive extraction (with `_nesting_depth` increment).
- Windows-specific checks (e.g., reserved names).
- More event types.

**Forbidden**:
- Adding deps.
- Relaxing defaults.
- Bypassing phases.

---

## 7. Testing Rules for Agents

- **All tests MUST run in Docker** (`make docker-test` or `make docker-test-env ENV=py312`).
- **Fixtures**: Craft malicious/edge ZIPs programmatically in `conftest.py` (use `struct`/`zipfile`).
- **Coverage**:
  - Unit: Per phase (e.g., `test_guard.py` for static checks).
  - Integration: End-to-end extraction, verify files/partials/events.
- **Must-haves for new tests**:
  - Legitimate passes.
  - Violation raises specific exception.
  - No disk pollution (atomic).
- **When responding**: If suggesting code, include test snippet.
- Coverage target: ≥95% (pytest-cov).

---

## 8. Key Files & What Agents Should Know

| File                              | Purpose for Agent                                      |
|-----------------------------------|--------------------------------------------------------|
| `src/safezip/_core.py`            | Usage entry: `SafeZipFile`, env overrides, events.    |
| `src/safezip/_guard.py`           | Static checks; extend for new malformed detections.   |
| `src/safezip/_sandbox.py`         | Path resolution; extend for new traversal types.      |
| `src/safezip/_streamer.py`        | Runtime extraction; extend for better ratio tracking. |
| `src/safezip/_exceptions.py`      | Custom errors; add new if needed (inherit `SafezipError`). |
| `src/safezip/_events.py`          | Events/policies; extend enum if new policies.         |
| `src/safezip/tests/conftest.py`   | **All** test archives crafted here (no commits).      |
| `pyproject.toml`                  | Setup, linters (ruff/mypy), tests (pytest-cov).       |
| `README.rst`                      | Usage examples; keep in sync with code.               |
| `CONTRIBUTING.rst`                | Dev guidelines; follow for PRs/tests.                 |

---

## 9. Prompt Templates You Can Use

**When explaining usage:**
> "You are an expert in secure file handling. Explain how to use safezip for [task], starting with defaults. Warn about limitations like data descriptors."

**When implementing a feature:**
> "Extend safezip with [feature]. Follow AGENTS.md workflow: Add to correct phase, update tests/docs. Preserve security."

**When testing/fixing:**
> "Reproduce [bug] with a conftest.py fixture, then fix. Add tests verifying atomicity and security events."

---

## 10. Quick Reference — Secure Defaults

```python
from safezip import SymlinkPolicy

SafeZipFile(
    file,
    max_file_size=1*1024**3,      # 1 GiB
    max_total_size=5*1024**3,     # 5 GiB
    max_files=10_000,
    max_per_member_ratio=200.0,
    max_total_ratio=200.0,
    max_nesting_depth=3,
    symlink_policy=SymlinkPolicy.REJECT,   # default
)
```

**Environment variables** (all supported):
`SAFEZIP_MAX_*`, `SAFEZIP_SYMLINK_POLICY` (reject/ignore/resolve_internal).

---

**You now have full context.**

When the user says “work on safezip” or asks about usage/features, **always start by quoting the relevant section of this AGENTS.md** so the conversation stays aligned with the security-first philosophy.
