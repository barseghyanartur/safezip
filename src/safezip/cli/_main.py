"""safezip CLI — hardened ZIP extraction from the command line."""

import argparse
import sys
from pathlib import Path

from safezip import SafeZipFile, SymlinkPolicy, safe_extract
from safezip._exceptions import SafezipError

__all__ = ("main",)

_SYMLINK_POLICIES = {
    "reject": SymlinkPolicy.REJECT,
    "ignore": SymlinkPolicy.IGNORE,
    "resolve_internal": SymlinkPolicy.RESOLVE_INTERNAL,
}


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="safezip",
        description="Hardened ZIP extraction — safe by default.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {_version()}",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # ------------------------------------------------------------------ extract
    ext = sub.add_parser("extract", help="Extract a ZIP archive safely.")
    ext.add_argument("archive", help="Path to the ZIP file.")
    ext.add_argument("destination", help="Directory to extract into.")
    ext.add_argument(
        "--max-file-size",
        type=int,
        metavar="BYTES",
        help="Max uncompressed size per member (default: 1 GiB).",
    )
    ext.add_argument(
        "--max-total-size",
        type=int,
        metavar="BYTES",
        help="Max total uncompressed size (default: 5 GiB).",
    )
    ext.add_argument(
        "--max-files",
        type=int,
        metavar="N",
        help="Max number of members (default: 10 000).",
    )
    ext.add_argument(
        "--max-per-member-ratio",
        type=float,
        metavar="RATIO",
        help="Max compression ratio per member (default: 200).",
    )
    ext.add_argument(
        "--max-total-ratio",
        type=float,
        metavar="RATIO",
        help="Max overall compression ratio (default: 200).",
    )
    ext.add_argument(
        "--max-nesting-depth",
        type=int,
        metavar="N",
        help="Max nested-archive depth (default: 3).",
    )
    ext.add_argument(
        "--symlink-policy",
        choices=list(_SYMLINK_POLICIES),
        default=None,
        metavar="POLICY",
        help=(
            "How to handle symlink entries: reject (default), ignore, resolve_internal."
        ),
    )
    ext.add_argument(
        "--password",
        metavar="PWD",
        help="Decryption password for encrypted archives.",
    )

    # --------------------------------------------------------------------- list
    lst = sub.add_parser("list", help="List members of a ZIP archive.")
    lst.add_argument("archive", help="Path to the ZIP file.")

    return parser


def _version() -> str:
    try:
        from safezip import __version__

        return __version__
    except ImportError:
        return "unknown"


def _cmd_extract(args: argparse.Namespace) -> int:
    kwargs: dict = {}

    for attr in (
        "max_file_size",
        "max_total_size",
        "max_files",
        "max_per_member_ratio",
        "max_total_ratio",
        "max_nesting_depth",
    ):
        val = getattr(args, attr, None)
        if val is not None:
            kwargs[attr] = val

    if args.symlink_policy is not None:
        kwargs["symlink_policy"] = _SYMLINK_POLICIES[args.symlink_policy]

    if args.password is not None:
        kwargs["password"] = args.password.encode()

    dest = Path(args.destination)
    dest.mkdir(parents=True, exist_ok=True)

    try:
        safe_extract(args.archive, dest, **kwargs)
    except SafezipError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"Extracted to {dest.resolve()}")
    return 0


def _cmd_list(args: argparse.Namespace) -> int:
    try:
        with SafeZipFile(args.archive) as zf:
            for name in zf.namelist():
                print(name)
    except SafezipError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    return 0


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    if args.command == "extract":
        sys.exit(_cmd_extract(args))
    elif args.command == "list":
        sys.exit(_cmd_list(args))
    else:  # pragma: no cover
        parser.print_help()
        sys.exit(1)
