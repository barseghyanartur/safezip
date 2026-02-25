"""Phase B: path resolution and symlink policy enforcement (the Sandbox)."""

import unicodedata
from pathlib import Path

from ._events import SymlinkPolicy
from ._exceptions import UnsafeZipError

__author__ = "Artur Barseghyan <artur.barseghyan@gmail.com>"
__copyright__ = "2026 Artur Barseghyan"
__license__ = "MIT"
__all__ = (
    "resolve_member_path",
    "check_symlink",
)

# Practical upper bound; real OS limits vary but 4096 is a safe conservative cap
_MAX_PATH_LENGTH = 4096


def resolve_member_path(
    base: Path,
    member_filename: str,
) -> Path:
    """Resolve and validate a ZIP member filename against *base*.

    Applies the full path normalisation pipeline:

    1. Unicode NFC normalisation (catch lookalike characters).
    2. Null-byte rejection.
    3. Reject absolute Unix paths (starting with ``/``) and absolute Windows
       paths (drive letter + slash, e.g. ``C:/``).
    4. Reject any ``..`` path component.
    5. Verify the resolved path is inside *base*.
    6. Reject paths whose resolved length exceeds ``_MAX_PATH_LENGTH``.

    :param base: The extraction root directory (must be absolute).
    :param member_filename: Raw filename string from the ZIP central directory.
    :returns: Resolved absolute Path inside *base*.
    :raises UnsafeZipError: If the filename is unsafe for any reason.
    """
    # 1. Unicode NFC normalisation
    try:
        normalized = unicodedata.normalize("NFC", member_filename)
    except (TypeError, ValueError) as err:
        raise UnsafeZipError(f"Cannot normalise filename: {member_filename!r}") from err

    # 2. Null-byte rejection
    if "\x00" in normalized:
        raise UnsafeZipError(f"Filename contains a null byte: {normalized!r}")

    # 3. Normalise separators
    _norm = normalized.replace("\\", "/")

    # Reject absolute Unix paths and UNC paths (start with '/')
    if _norm.startswith("/"):
        raise UnsafeZipError(f"Absolute path detected in filename: {member_filename!r}")

    # Reject absolute Windows paths with drive letters (e.g. "C:/Windows")
    if len(_norm) >= 3 and _norm[1] == ":" and _norm[2] == "/" and _norm[0].isalpha():
        raise UnsafeZipError(
            f"Absolute Windows path detected in filename: {member_filename!r}"
        )

    parts = _norm.split("/")

    # Strip Windows-style relative drive
    # references (e.g. "C:relpath") - defence-in-depth
    clean_parts = []
    for part in parts:
        # Skip empty parts (double-slashes) and current-dir dots
        if not part or part == ".":
            continue
        # Reject parent-directory traversal
        if part == "..":
            raise UnsafeZipError(
                f"Path traversal detected in filename: {member_filename!r}"
            )
        # Strip Windows-style relative drive
        # references (e.g. "C:relpath" → "relpath")
        if len(part) >= 2 and part[1] == ":" and part[0].isalpha():
            part = part[2:]
            if not part:
                continue
        clean_parts.append(part)

    if not clean_parts:
        raise UnsafeZipError(f"Filename resolves to empty path: {member_filename!r}")

    # 4. Build the resolved path
    resolved = base
    for part in clean_parts:
        resolved = resolved / part

    # 5. Confirm the resolved path is inside base
    try:
        resolved.relative_to(base)
    except ValueError as err:
        raise UnsafeZipError(
            f"Resolved path escapes base directory: {resolved!r} is not under {base!r}"
        ) from err

    # 6. Path length check
    if len(str(resolved)) > _MAX_PATH_LENGTH:
        raise UnsafeZipError(
            f"Resolved path is too long ({len(str(resolved))} chars): "
            f"{str(resolved)[:120]!r}..."
        )

    return resolved


def check_symlink(
    extracted_path: Path,
    base: Path,
    policy: SymlinkPolicy,
) -> bool:
    """
    Check whether *extracted_path* is (or contains) a symlink, & apply policy.

    :param extracted_path: The path that was just extracted.
    :param base: The extraction root directory.
    :param policy: The configured symlink policy.
    :returns: ``True`` if the member should be skipped (IGNORE policy).
    :raises UnsafeZipError: If REJECT policy or chain exits base directory.
    """
    if not extracted_path.is_symlink():
        return False

    if policy == SymlinkPolicy.REJECT:
        raise UnsafeZipError(
            f"Symlink detected and symlink_policy is REJECT: {extracted_path}"
        )

    if policy == SymlinkPolicy.IGNORE:
        return True  # caller should skip this member

    # RESOLVE_INTERNAL: follow the full chain and verify every hop
    _verify_symlink_chain(extracted_path, base)
    return False


def _verify_symlink_chain(link_path: Path, base: Path) -> None:
    """Verify the full symlink chain from *link_path* stays inside *base*.

    Follows every link until a non-symlink is reached or an escape is detected.

    :raises UnsafeZipError: If any link in the chain exits *base*.
    """
    visited = set()
    current = link_path

    while current.is_symlink():
        real = str(current.resolve())
        if real in visited:
            # Cycle detected; treat as unsafe
            raise UnsafeZipError(
                f"Symlink cycle detected at {current}: refusing to follow further."
            )
        visited.add(real)

        try:
            current.resolve().relative_to(base.resolve())
        except ValueError as err:
            raise UnsafeZipError(
                f"Symlink chain for {link_path} exits the base directory "
                f"at {current} → {current.resolve()}"
            ) from err
        current = current.resolve()
