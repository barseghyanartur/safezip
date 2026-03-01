"""Security event types and symlink policy enum."""

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional

__author__ = "Artur Barseghyan <artur.barseghyan@gmail.com>"
__copyright__ = "2026 Artur Barseghyan"
__license__ = "MIT"
__all__ = (
    "SecurityEvent",
    "SymlinkPolicy",
    "SecurityEventCallback",
)


class SymlinkPolicy(Enum):
    """Controls how symlink members in archives are handled."""

    REJECT = "reject"
    """Any symlink entry raises UnsafeZipError (default)."""

    IGNORE = "ignore"
    """Symlink entries are silently skipped."""

    RESOLVE_INTERNAL = "resolve_internal"
    """Symlink entries are extracted as regular files containing the raw link-target
    bytes.  No OS symlink is created on disk."""


@dataclass
class SecurityEvent:
    """Minimal, privacy-safe payload emitted to the on_security_event callback.

    Deliberately excludes filenames, paths, and member names so that
    forwarding this to a third-party service cannot leak confidential
    filesystem information.
    """

    event_type: str
    """Short string identifying what happened, e.g. 'zip_slip_detected'."""

    archive_hash: str
    """First 16 hex characters of the SHA-256 hash of the archive path/name."""

    timestamp: float = field(default_factory=time.time)
    """Wall-clock time at the moment of detection (time.time())."""


# Type alias for the optional callback
SecurityEventCallback = Optional[Callable[[SecurityEvent], None]]
