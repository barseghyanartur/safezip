"""SafeZipFile: the public hardened wrapper around zipfile.ZipFile."""

import hashlib
import logging
import os
import stat
import zipfile
from contextlib import suppress
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


def _archive_stem(name: str) -> str:
    """Strip the archive extension from *name*, returning the base stem.

    Handles single extensions only (ZIP archives do not use compound
    extensions like .tar.gz), but normalises consistently.

    Examples::

        archive.zip  → archive
        lib.whl      → lib
        app.jar      → app
        data.csv     → data.csv   (non-archive extension unchanged)
    """
    p = Path(name)
    if p.suffix.lower() in _ARCHIVE_EXTENSIONS:
        return p.stem
    return name


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


def _env_bool(name: str, default: bool) -> bool:
    val = os.environ.get(name)
    if val is None:
        return default
    if val.lower() in ("1", "true", "yes", "on"):
        return True
    if val.lower() in ("0", "false", "no", "off"):
        return False
    log.warning(
        "Ignoring unrecognised %s value %r; using default %r.",
        name,
        val,
        default,
    )
    return default


def _sanitise_mode(path: Path, *, strip_special_bits: bool = True) -> None:
    """Strip setuid/setgid/sticky bits from *path* if requested."""
    if not strip_special_bits:
        return
    try:
        current = path.stat().st_mode
        safe = current & ~(stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX)
        if safe != current:
            os.chmod(path, safe)
    except OSError:
        pass  # best-effort; extraction already succeeded


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


_DEFAULT_MAX_FILE_SIZE: int = _env_int("SAFEZIP_MAX_FILE_SIZE", 1 * 1024**3)
_DEFAULT_MAX_TOTAL_SIZE: int = _env_int("SAFEZIP_MAX_TOTAL_SIZE", 5 * 1024**3)
_DEFAULT_MAX_FILES: int = _env_int("SAFEZIP_MAX_FILES", 10_000)
_DEFAULT_MAX_PER_MEMBER_RATIO: float = _env_float("SAFEZIP_MAX_PER_MEMBER_RATIO", 200.0)
_DEFAULT_MAX_TOTAL_RATIO: float = _env_float("SAFEZIP_MAX_TOTAL_RATIO", 200.0)
_DEFAULT_MAX_NESTING_DEPTH: int = _env_int("SAFEZIP_MAX_NESTING_DEPTH", 3)
_DEFAULT_SYMLINK_POLICY: SymlinkPolicy = _env_symlink_policy(SymlinkPolicy.REJECT)
_DEFAULT_RECURSIVE: bool = _env_bool("SAFEZIP_RECURSIVE", False)


def _archive_hash(file: Union[str, os.PathLike, BinaryIO]) -> str:
    """Return first 16 hex characters of SHA-256 of archive content (first 64 KiB).

    Content-based hashing ensures different files at the same path produce
    different hashes in SecurityEvent records.
    """
    h = hashlib.sha256()
    if isinstance(file, (str, os.PathLike)):
        try:
            with open(file, "rb") as fh:
                h.update(fh.read(65536))
        except OSError:
            h.update(str(file).encode())
        return h.hexdigest()[:16]

    pos = file.tell()
    try:
        h.update(file.read(65536))
    finally:
        with suppress(OSError):
            file.seek(pos)
    return h.hexdigest()[:16]


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
        recursive: Optional[bool] = None,
        strip_special_bits: bool = True,
    ) -> None:
        # Resolve limits: constructor arg > env var > module-level default
        # Env vars are read at runtime to support test monkeypatching
        self._max_file_size = (
            max_file_size
            if max_file_size is not None
            else _env_int("SAFEZIP_MAX_FILE_SIZE", _DEFAULT_MAX_FILE_SIZE)
        )
        self._max_total_size = (
            max_total_size
            if max_total_size is not None
            else _env_int("SAFEZIP_MAX_TOTAL_SIZE", _DEFAULT_MAX_TOTAL_SIZE)
        )
        self._max_files = (
            max_files
            if max_files is not None
            else _env_int("SAFEZIP_MAX_FILES", _DEFAULT_MAX_FILES)
        )
        self._max_per_member_ratio = (
            max_per_member_ratio
            if max_per_member_ratio is not None
            else _env_float(
                "SAFEZIP_MAX_PER_MEMBER_RATIO", _DEFAULT_MAX_PER_MEMBER_RATIO
            )
        )
        self._max_total_ratio = (
            max_total_ratio
            if max_total_ratio is not None
            else _env_float("SAFEZIP_MAX_TOTAL_RATIO", _DEFAULT_MAX_TOTAL_RATIO)
        )
        self._max_nesting_depth = (
            max_nesting_depth
            if max_nesting_depth is not None
            else _env_int("SAFEZIP_MAX_NESTING_DEPTH", _DEFAULT_MAX_NESTING_DEPTH)
        )
        self._symlink_policy = (
            symlink_policy
            if symlink_policy is not None
            else _env_symlink_policy(_DEFAULT_SYMLINK_POLICY)
        )
        self._recursive = (
            recursive
            if recursive is not None
            else _env_bool("SAFEZIP_RECURSIVE", _DEFAULT_RECURSIVE)
        )
        self._strip_special_bits = strip_special_bits
        self._password = password
        self._on_security_event = on_security_event
        self._archive_hash = _archive_hash(file)
        self._nesting_depth = _nesting_depth

        if _nesting_depth > self._max_nesting_depth:
            self._emit_event("nesting_depth_exceeded")
            log.warning(
                "Nesting depth limit exceeded",
                extra={
                    "event": "nesting_depth_exceeded",
                    "nesting_depth": _nesting_depth,
                    "max_nesting_depth": self._max_nesting_depth,
                    "archive_hash": self._archive_hash,
                },
            )
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
        :raises TypeError: If path is None.
        """
        if path is None:
            raise TypeError(
                "SafeZipFile.extract() requires an explicit 'path' argument."
            )
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
        :raises TypeError: If path is None.
        """
        if path is None:
            raise TypeError(
                "SafeZipFile.extractall() requires an explicit 'path' argument; "
                "extraction to the current working directory is not permitted."
            )
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
                # Content-based detection (avoids extension-spoofing)
                if zipfile.is_zipfile(tmp):
                    nested_dest = dest.parent / _archive_stem(dest.name)
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

        # Post-extraction permission sanitisation
        if not dest.is_symlink():
            _sanitise_mode(dest, strip_special_bits=self._strip_special_bits)

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
