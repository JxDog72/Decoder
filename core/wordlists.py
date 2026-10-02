"""Find password wordlists that are already on this machine.

The scan matches the idea in HTB Helper: known files first, then the usual
Kali/Parrot folders. Nothing is downloaded or decompressed.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


READY_NAMES = (
    "/usr/share/wordlists/rockyou.txt",
    "/usr/share/wordlists/fasttrack.txt",
    "/usr/share/john/password.lst",
    "/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt",
    "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-10000.txt",
    "/usr/share/seclists/Passwords/Leaked-Databases/rockyou-75.txt",
)

GZIP_NAMES = (
    "/usr/share/wordlists/rockyou.txt.gz",
)

SCAN_DIRS = (
    "/usr/share/wordlists",
    "/usr/share/john",
    "/usr/share/seclists/Passwords",
)

PRIORITY = ("rockyou.txt", "password.lst", "fasttrack", "10k", "top-100", "common-credential")
MAX_LISTS = 40
TEXT_SUFFIXES = {".txt", ".lst", ".dic"}


@dataclass(frozen=True)
class WordlistHit:
    path: str
    kind: str  # "ready" or "gzip"
    note: str


def platform_note() -> str:
    if os.name == "nt":
        return (
            "This PC is Windows. Lists turn up under Decoder\\wordlists, "
            "C:\\wordlists, and C:\\Tools\\wordlists, or any file you browse to. "
            "The Kali paths (/usr/share/wordlists/rockyou.txt and SecLists Passwords) "
            "are checked when this same app runs on Linux."
        )
    return (
        "This PC is Linux. Decoder checks the same places HTB Helper does: "
        "/usr/share/wordlists, John's password.lst, and /usr/share/seclists/Passwords."
    )


def default_scan_dirs(app_dir: Path | None = None) -> list[Path]:
    home = Path.home()
    folders = [
        Path(item) for item in SCAN_DIRS
    ]
    folders.extend(
        [
            home / "wordlists",
            home / "SecLists" / "Passwords",
            home / "seclists" / "Passwords",
            Path("C:/wordlists"),
            Path("C:/Tools/wordlists"),
            Path("C:/Tools/SecLists/Passwords"),
        ]
    )
    if app_dir is not None:
        folders.append(app_dir / "wordlists")
    return folders


def locate_wordlists(
    *,
    app_dir: Path | None = None,
    named: tuple[str, ...] | None = None,
    gzip_names: tuple[str, ...] | None = None,
    scan_dirs: list[Path] | None = None,
) -> list[WordlistHit]:
    """Return ready lists first, then a compressed rockyou if that is all that exists."""
    ready: list[str] = []
    gzipped: list[str] = []
    seen: set[str] = set()

    def add(path: Path, bucket: list[str]) -> None:
        try:
            if not path.is_file():
                return
            resolved = str(path.resolve())
        except OSError:
            return
        key = resolved.lower()
        if key in seen:
            return
        seen.add(key)
        bucket.append(resolved)

    for item in named if named is not None else READY_NAMES:
        add(Path(item), ready)

    folders = scan_dirs if scan_dirs is not None else default_scan_dirs(app_dir)
    discovered: list[str] = []
    for folder in folders:
        try:
            if not folder.is_dir():
                continue
        except OSError:
            continue
        for dirpath, dirnames, filenames in os.walk(folder):
            dirnames[:] = [
                name
                for name in dirnames
                if name not in {".git", ".svn", "node_modules", "__pycache__"}
            ]
            try:
                depth = len(Path(dirpath).resolve().relative_to(folder.resolve()).parts)
            except (OSError, ValueError):
                depth = 99
            if depth > 3:
                dirnames[:] = []
                continue
            for name in filenames:
                if Path(name).suffix.lower() not in TEXT_SUFFIXES:
                    continue
                discovered.append(str(Path(dirpath) / name))

    def rank(path: str) -> tuple[int, str]:
        lower = path.lower()
        for index, token in enumerate(PRIORITY):
            if token in lower:
                return (index, lower)
        return (len(PRIORITY), lower)

    discovered.sort(key=rank)
    for item in discovered:
        if len(ready) >= MAX_LISTS:
            break
        add(Path(item), ready)

    hits = [WordlistHit(path, "ready", "ready to pass as a wordlist") for path in ready]

    txt_names = {Path(path).name.lower() for path in ready}
    for item in gzip_names if gzip_names is not None else GZIP_NAMES:
        path = Path(item)
        if path.name.lower().removesuffix(".gz") in txt_names:
            continue
        add(path, gzipped)
    for path in gzipped:
        hits.append(
            WordlistHit(
                path,
                "gzip",
                "compressed. Copy this, then run it yourself: gzip -dk " + path,
            )
        )
    return hits
