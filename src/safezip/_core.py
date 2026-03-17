"""SafeZipFile: the public hardened wrapper around zipfile.ZipFile."""

import hashlib
import logging
import os
import stat
import zipfile
from pathlib import Path
from typing import BinaryIO, Optional, Union

from ._events import SecurityEvent, SecurityEventCallback, SymlinkPolicy
from ._exceptions import (
    CompressionRatioError,
    FileCountExceededError,
    FileSizeExceededError,
    MalformedArchiveError,
    NestingDepthError,
    TotalSizeExceededError,
    UnsafeZipError,
)
from ._guard import validate_archive
from ._sandbox import check_symlink, resolve_member_path
from ._streamer import CumulativeCounters, stream_extract_member

__author__ = "Artur Barseghyan <artur.barseghyan@gmail.com>"
__copyright__ = "2026 Artur Barseghyan"
__license__ = "MIT"
__all__ = (
    "SafeZipFile",
    "safe_extract",
)

log = logging.getLogger("safezip.security")

_ARCHIVE_EXTENSIONS = frozenset(
    {".zip", ".jar", ".war", ".ear", ".apk", ".aar", ".whl", ".egg"}
)


def _env_int(name: str, default: int) -> int:
    val = os.environ.get(name)
    if val is None:
        return default
    try:
        return int(val)
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    val = os.environ.get(name)
    if val is None:
        return default
    try:
        return float(val)
    except ValueError:
        return default


def _env_symlink_policy(default: SymlinkPolicy) -> SymlinkPolicy:
    """Read SAFEZIP_SYMLINK_POLICY from the environment.

    Accepted values (case-insensitive): ``reject``, ``ignore``,
    ``resolve_internal``.  Any other value is logged and ignored.
    """
    val = os.environ.get("SAFEZIP_SYMLINK_POLICY")
    if val is None:
        return default
    mapping = {
        "reject": SymlinkPolicy.REJECT,
        "ignore": SymlinkPolicy.IGNORE,
        "resolve_internal": SymlinkPolicy.RESOLVE_INTERNAL,
    }
    resolved = mapping.get(val.lower())
    if resolved is None:
        log.warning(
            "Ignoring unrecognised SAFEZIP_SYMLINK_POLICY value %r; using default %r.",
            val,
            default.value,
        )
        return default
    return resolved


def _archive_hash(file: Union[str, os.PathLike, BinaryIO]) -> str:
    """Return first 16 hex characters of SHA-256 of the archive path/name."""
    if isinstance(file, (str, os.PathLike)):
        return hashlib.sha256(str(file).encode()).hexdigest()[:16]
    name = getattr(file, "name", repr(file))
    return hashlib.sha256(str(name).encode()).hexdigest()[:16]


class SafeZipFile:
    """A hardened, composition-based wrapper around :class:`zipfile.ZipFile`.

    All defences are enabled by default.  Limits can be relaxed by passing
    explicit constructor arguments or by setting environment variables.

    .. note::

        This class intentionally does **not** expose ``open()``, ``read()``,
        or any write-mode methods from the underlying ``zipfile.ZipFile``.
        Callers needing lower-level access must use ``zipfile.ZipFile``
        directly, accepting the associated risks.
    """

    def __init__(
        self,
        file: Union[str, os.PathLike, BinaryIO],
        mode: str = "r",
        *,
        max_file_size: Optional[int] = None,
        max_total_size: Optional[int] = None,
        max_files: Optional[int] = None,
        max_per_member_ratio: Optional[float] = None,
        max_total_ratio: Optional[float] = None,
        max_nesting_depth: Optional[int] = None,
        symlink_policy: Optional[SymlinkPolicy] = None,
        password: Optional[bytes] = None,
        on_security_event: SecurityEventCallback = None,
        _nesting_depth: int = 0,
        recursive: bool = False,
    ) -> None:
        # Resolve limits: constructor arg > env var > hardcoded default
        self._max_file_size = (
            max_file_size
            if max_file_size is not None
            else _env_int("SAFEZIP_MAX_FILE_SIZE", 1 * 1024**3)
        )
        self._max_total_size = (
            max_total_size
            if max_total_size is not None
            else _env_int("SAFEZIP_MAX_TOTAL_SIZE", 5 * 1024**3)
        )
        self._max_files = (
            max_files
            if max_files is not None
            else _env_int("SAFEZIP_MAX_FILES", 10_000)
        )
        self._max_per_member_ratio = (
            max_per_member_ratio
            if max_per_member_ratio is not None
            else _env_float("SAFEZIP_MAX_PER_MEMBER_RATIO", 200.0)
        )
        self._max_total_ratio = (
            max_total_ratio
            if max_total_ratio is not None
            else _env_float("SAFEZIP_MAX_TOTAL_RATIO", 200.0)
        )
        self._max_nesting_depth = (
            max_nesting_depth
            if max_nesting_depth is not None
            else _env_int("SAFEZIP_MAX_NESTING_DEPTH", 3)
        )
        self._symlink_policy = (
            symlink_policy
            if symlink_policy is not None
            else _env_symlink_policy(SymlinkPolicy.REJECT)
        )
        self._password = password
        self._on_security_event = on_security_event
        self._archive_hash = _archive_hash(file)
        self._recursive = recursive
        self._nesting_depth = _nesting_depth

        if _nesting_depth > self._max_nesting_depth:
            raise NestingDepthError(
                f"Nested archive depth {_nesting_depth} exceeds "
                f"max_nesting_depth={self._max_nesting_depth}."
            )

        try:
            self._zf = zipfile.ZipFile(file, mode)
        except zipfile.BadZipFile as exc:
            raise MalformedArchiveError(f"Cannot open archive: {exc}") from exc

        # Run the Guard immediately on open
        try:
            validate_archive(self._zf, self._max_files, self._max_file_size)
        except FileCountExceededError:
            self._emit_event("file_count_exceeded")
            raise
        except FileSizeExceededError:
            self._emit_event("declared_size_exceeded")
            raise
        except MalformedArchiveError:
            self._emit_event("malformed_archive")
            raise

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> "SafeZipFile":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def close(self) -> None:
        """Close the underlying archive."""
        self._zf.close()

    # ------------------------------------------------------------------
    # Read-only inspection (safe subset of zipfile.ZipFile)
    # ------------------------------------------------------------------

    def namelist(self) -> list:
        """Return a list of archive member names."""
        return self._zf.namelist()

    def infolist(self) -> list:
        """Return a list of ZipInfo objects for all archive members."""
        return self._zf.infolist()

    def getinfo(self, name: str) -> zipfile.ZipInfo:
        """Return a ZipInfo object for *name*."""
        return self._zf.getinfo(name)

    # ------------------------------------------------------------------
    # Extraction
    # ------------------------------------------------------------------

    def extract(
        self,
        member: Union[str, zipfile.ZipInfo],
        path: Union[str, os.PathLike],
        *,
        pwd: Optional[bytes] = None,
    ) -> str:
        """Safely extract a single *member* to *path*.

        :param member: Member name string or ZipInfo object.
        :param path: Destination directory (required; no default).
        :param pwd: Optional decryption password.
        :returns: The path to the extracted file as a string.
        :raises UnsafeZipError: On path traversal, absolute paths, or symlinks.
        :raises FileSizeExceededError: If the member is too large.
        :raises CompressionRatioError: If the compression ratio is too high.
        """
        base = Path(path).resolve()
        counters = CumulativeCounters()
        info = (
            member if isinstance(member, zipfile.ZipInfo) else self._zf.getinfo(member)
        )
        dest = self._extract_one(info, base, counters, pwd or self._password)
        return str(dest)

    def extractall(
        self,
        path: Union[str, os.PathLike],
        members: Optional[list] = None,
        *,
        pwd: Optional[bytes] = None,
    ) -> None:
        """Safely extract all (or selected) members to *path*.

        :param path: Destination directory (required; no default).
        :param members: Optional list of member names or ZipInfo objects.
        :param pwd: Optional decryption password.
        :raises UnsafeZipError: On path traversal, absolute paths, or symlinks.
        :raises FileSizeExceededError: If any member is too large.
        :raises TotalSizeExceededError: If total extracted size is too large.
        :raises CompressionRatioError: If any ratio limit is exceeded.
        """
        base = Path(path).resolve()
        counters = CumulativeCounters()
        effective_pwd = pwd or self._password

        if members is None:
            infos = self._zf.infolist()
        else:
            infos = [
                m if isinstance(m, zipfile.ZipInfo) else self._zf.getinfo(m)
                for m in members
            ]

        for info in infos:
            self._extract_one(info, base, counters, effective_pwd)

    def _extract_one(
        self,
        info: zipfile.ZipInfo,
        base: Path,
        counters: CumulativeCounters,
        pwd: Optional[bytes],
    ) -> Path:
        """Core per-member extraction logic."""
        # Directories - create and skip streaming
        if info.filename.endswith("/"):
            dest = resolve_member_path(base, info.filename.rstrip("/"))
            dest.mkdir(parents=True, exist_ok=True)
            return dest

        # Validate and resolve the destination path (Sandbox / Phase B)
        try:
            dest = resolve_member_path(base, info.filename)
        except UnsafeZipError:
            self._emit_event("zip_slip_detected")
            log.warning(
                "Path traversal attempt blocked",
                extra={
                    "event": "zip_slip_detected",
                    "member": info.filename[:256],
                    "archive_hash": self._archive_hash,
                },
            )
            raise

        # Check for symlinks in the *source* entry
        # (detect if the ZIP entry itself is stored as a symlink)
        attr = (info.external_attr >> 16) & 0xFFFF
        is_symlink_entry = bool(attr and stat.S_ISLNK(attr))

        if is_symlink_entry:
            if self._symlink_policy == SymlinkPolicy.REJECT:
                self._emit_event("symlink_rejected")
                log.warning(
                    "Symlink entry rejected",
                    extra={
                        "event": "symlink_rejected",
                        "member": info.filename[:256],
                        "archive_hash": self._archive_hash,
                    },
                )
                raise UnsafeZipError(
                    f"Symlink entry {info.filename!r} rejected (symlink_policy=REJECT)."
                )
            if self._symlink_policy == SymlinkPolicy.IGNORE:
                self._emit_event("symlink_ignored")
                log.warning(
                    "Symlink entry skipped (IGNORE policy)",
                    extra={
                        "event": "symlink_ignored",
                        "member": info.filename[:256],
                        "archive_hash": self._archive_hash,
                    },
                )
                return dest

        # Nested archive guard
        suffix = Path(info.filename).suffix.lower()
        is_archive_extension = suffix in _ARCHIVE_EXTENSIONS

        # Non-recursive: keep the debug log but don't gate on content
        if not self._recursive:
            if is_archive_extension:
                log.debug(
                    "Nested archive detected: %r - extracting as raw file,"
                    " not recursing.",
                    info.filename,
                )
        else:
            # Recursive path: stream to temp first, then content-detect
            tmp = dest.parent / (
                f"{dest.name}.safezip_tmp_{os.getpid()}_{os.urandom(4).hex()}"
            )
            try:
                stream_extract_member(
                    self._zf,
                    info,
                    tmp,
                    max_file_size=self._max_file_size,
                    max_per_member_ratio=self._max_per_member_ratio,
                    max_total_size=self._max_total_size,
                    max_total_ratio=self._max_total_ratio,
                    counters=counters,
                    pwd=pwd,
                )
                # Content-based detection (avoids extension-spoofing)
                if zipfile.is_zipfile(tmp):
                    nested_dest = dest.parent / dest.stem
                    nested_dest.mkdir(parents=True, exist_ok=True)
                    with SafeZipFile(
                        tmp,
                        max_file_size=self._max_file_size,
                        max_total_size=self._max_total_size,
                        max_files=self._max_files,
                        max_per_member_ratio=self._max_per_member_ratio,
                        max_total_ratio=self._max_total_ratio,
                        max_nesting_depth=self._max_nesting_depth,
                        symlink_policy=self._symlink_policy,
                        password=self._password,
                        on_security_event=self._on_security_event,
                        recursive=True,
                        _nesting_depth=self._nesting_depth + 1,
                    ) as nested_zf:
                        nested_zf.extractall(nested_dest, pwd=pwd)
                    return nested_dest
                else:
                    # Not a ZIP — rename temp to final destination as a regular file
                    tmp.replace(dest)
                    return dest
            finally:
                tmp.unlink(missing_ok=True)

        # Stream-extract with all runtime monitors (Phase C)
        try:
            stream_extract_member(
                self._zf,
                info,
                dest,
                max_file_size=self._max_file_size,
                max_per_member_ratio=self._max_per_member_ratio,
                max_total_size=self._max_total_size,
                max_total_ratio=self._max_total_ratio,
                counters=counters,
                pwd=pwd,
            )
        except FileSizeExceededError:
            self._emit_event("file_size_exceeded")
            log.warning(
                "Member size limit exceeded during streaming",
                extra={
                    "event": "file_size_exceeded",
                    "member": info.filename[:256],
                    "archive_hash": self._archive_hash,
                },
            )
            raise
        except TotalSizeExceededError:
            self._emit_event("total_size_exceeded")
            log.warning(
                "Cumulative extraction size limit exceeded during streaming",
                extra={
                    "event": "total_size_exceeded",
                    "member": info.filename[:256],
                    "archive_hash": self._archive_hash,
                },
            )
            raise
        except CompressionRatioError:
            self._emit_event("compression_ratio_exceeded")
            log.warning(
                "Compression ratio limit exceeded during streaming",
                extra={
                    "event": "compression_ratio_exceeded",
                    "member": info.filename[:256],
                    "archive_hash": self._archive_hash,
                },
            )
            raise

        # Post-extraction symlink check (RESOLVE_INTERNAL policy)
        if dest.is_symlink() and self._symlink_policy == SymlinkPolicy.RESOLVE_INTERNAL:
            skip = check_symlink(dest, base, self._symlink_policy)
            if skip:
                dest.unlink(missing_ok=True)

        return dest

    def _emit_event(self, event_type: str) -> None:
        """Emit a SecurityEvent to the configured callback (if any)."""
        if self._on_security_event is None:
            return
        event = SecurityEvent(
            event_type=event_type,
            archive_hash=self._archive_hash,
        )
        try:
            self._on_security_event(event)
        except Exception:
            log.exception(
                "on_security_event callback raised an exception "
                "(event_type=%r); suppressing to preserve security "
                "enforcement.",
                event_type,
            )


def safe_extract(
    archive: Union[str, os.PathLike, BinaryIO],
    destination: Union[str, os.PathLike],
    **kwargs,
) -> None:
    """
    Convenience func: extract *archive* to *destination* using safe defaults.

    All keyword arguments are forwarded to :class:`SafeZipFile`.

    :param archive: Path to the ZIP file, or a file-like binary object.
    :param destination: Directory to extract into.
    """
    with SafeZipFile(archive, **kwargs) as zf:
        zf.extractall(destination)
