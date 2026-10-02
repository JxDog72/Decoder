"""Identify a challenge file from its bytes, then show the next local step.

This covers the Hack the Gibson path: a base64 peel, an IBM XMI, a zip,
repeating 0x40, and an EBCDIC (CP037) preview. It also names common Windows
forensic containers. It does not unpack someone else's registry into Windows.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass


READ_LIMIT = 2_000_000

# (offset, magic, label, next step)
SIGNATURES: tuple[tuple[int, bytes, str, str], ...] = (
    (0, b"PK\x03\x04", "ZIP", "Rename a copy to .zip and unzip it. Office, JAR, and APK files are zip containers too."),
    (0, b"PK\x05\x06", "ZIP (empty central directory)", "The file claims to be a zip with no members."),
    (0, b"\x1f\x8b", "gzip", "gzip -dk FILE, or open it with 7-Zip."),
    (0, b"BZh", "bzip2", "bunzip2, or open it with 7-Zip."),
    (0, b"\xfd7zXZ\x00", "xz", "xz -dk FILE, or open it with 7-Zip."),
    (0, b"%PDF", "PDF", "pdfinfo and pdftotext if poppler is installed. A locked PDF needs pdf2john, then the Crack tab."),
    (0, b"\x89PNG\r\n\x1a\n", "PNG", "strings FILE, and look for a trailing zip. Stego challenges often hide text after the image."),
    (0, b"\xff\xd8\xff", "JPEG", "strings FILE. A camera JPEG may also have EXIF."),
    (0, b"GIF87a", "GIF", "strings FILE."),
    (0, b"GIF89a", "GIF", "strings FILE."),
    (0, b"Rar!\x1a\x07", "RAR", "Extract with 7-Zip or unrar. A passworded RAR needs rar2john, then the Crack tab."),
    (0, b"7z\xbc\xaf\x27\x1c", "7-Zip", "Extract with 7-Zip."),
    (0, b"MZ", "Windows PE (EXE or DLL)", "This is a Windows program. strings is the first look. Do not run an unknown CTF binary on your host."),
    (0, b"\x7fELF", "Linux ELF", "file and strings. Do not execute an unknown CTF binary on your host."),
    (0, b"SQLite format 3\x00", "SQLite", "sqlite3 FILE \".tables\" then query. Browser history and some app databases use this."),
    (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE Compound File", "Old Word, Excel, or MSI. A locked Office file needs office2john, then the Crack tab."),
    (0, b"ID3", "MP3", "strings, or a hex dump of the tag."),
    (0, b"\xd4\xc3\xb2\xa1", "pcap (little-endian)", "Open in Wireshark. This is network traffic, not a Decoder crack."),
    (0, b"\xa1\xb2\xc3\xd4", "pcap (big-endian)", "Open in Wireshark."),
    (0, b"\x0a\x0d\x0d\x0a", "pcapng", "Open in Wireshark."),
    (0, b"ElfFile\x00", "Windows Event Log (EVTX)", "Windows: wevtutil qe FILE /lf:true /f:text /c:30. Search the text for the event id and the username."),
    (0, b"regf", "Windows Registry hive", "Read it with a hive viewer. Do not import a challenge hive into your live Windows registry."),
    (0, b"SCCA", "Windows Prefetch (older)", "The executable name is inside the file. strings is enough for a first look."),
    (0, b"MAM\x04", "Windows Prefetch (compressed)", "Windows 10+ prefetch. strings may still show the program name."),
    (0, b"INMR01", "IBM NETDATA / XMIT (ASCII)", "extractxmi FILE. That tool comes from pip install xmi-reader inside a virtual environment."),
    (0, bytes.fromhex("c9d5d4d9f0f1"), "IBM NETDATA / XMIT (EBCDIC INMR01)", "The header is EBCDIC. extractxmi can open a real XMI. A base64 peel may be required first."),
    (0, b"-----BEGIN", "PEM text", "Certificate or key. Read the label on the first line."),
    (0, b"\x4c\x00\x00\x00\x01\x14\x02\x00", "Windows shortcut (LNK)", "The target path is stored as text. strings will show it."),
    (0, b"FILE0", "NTFS $MFT record", "A Master File Table fragment. A forensic viewer reads the filenames."),
)


@dataclass(frozen=True)
class SignatureHit:
    label: str
    next_step: str


def _hits(data: bytes) -> list[SignatureHit]:
    found: list[SignatureHit] = []
    for offset, magic, label, step in SIGNATURES:
        end = offset + len(magic)
        if len(data) >= end and data[offset:end] == magic:
            found.append(SignatureHit(label, step))
    if len(data) >= 262 and data[257:262] == b"ustar":
        found.append(SignatureHit("tar (ustar)", "tar -xf FILE"))
    if len(data) >= 8 and data[4:8] == b"ftyp":
        found.append(SignatureHit("MP4 / MOV", "strings FILE, or open it in a media player you trust."))
    return found


def _compact_base64(text: str) -> str | None:
    compact = re.sub(r"\s+", "", text.strip())
    if len(compact) < 16 or len(compact) % 4 != 0:
        return None
    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", compact):
        return None
    return compact


def looks_like_base64(text: str) -> bool:
    compact = _compact_base64(text)
    if compact is None:
        return False
    return compact.endswith("=") or len(compact) >= 64


def peel_base64(text: str) -> bytes | None:
    """Decode a base64 blob. A short string must peel into a known file header."""
    compact = _compact_base64(text)
    if compact is None:
        return None
    try:
        raw = base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError):
        return None
    if not raw:
        return None
    if _hits(raw):
        return raw
    if not (compact.endswith("=") or len(compact) >= 64):
        return None
    sample = raw[:200]
    odd = sum(1 for byte in sample if byte < 9 or byte > 126)
    if odd * 4 > len(sample):
        return raw
    return None


def hex_dump(data: bytes, *, limit: int = 256) -> str:
    view = data[:limit]
    lines: list[str] = []
    for offset in range(0, len(view), 16):
        chunk = view[offset : offset + 16]
        hex_part = " ".join(f"{byte:02x}" for byte in chunk)
        text = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in chunk)
        lines.append(f"{offset:08x}  {hex_part:<47}  {text}")
    if len(data) > limit:
        lines.append(f"... {len(data) - limit} more bytes not shown")
    return "\n".join(lines)


def ebcdic_hint(data: bytes) -> str | None:
    sample = data[:512]
    if not sample:
        return None
    spaces = sample.count(0x40)
    ascii_letters = sum(1 for byte in sample if 65 <= byte <= 90 or 97 <= byte <= 122)
    # EBCDIC uppercase A–Z sits in C1–C9, D1–D9, and E2–E9, not in ASCII.
    ebcdic_upper = sum(
        1
        for byte in sample
        if 0xC1 <= byte <= 0xC9 or 0xD1 <= byte <= 0xD9 or 0xE2 <= byte <= 0xE9
    )
    padded = spaces >= 8 and spaces > ascii_letters
    letters = ebcdic_upper >= 4 and ebcdic_upper > ascii_letters
    if padded or letters:
        return (
            f"0x40 appears {spaces} times in the first {len(sample)} bytes, "
            f"with {ebcdic_upper} EBCDIC uppercase letters. "
            "In EBCDIC, 0x40 is a space. ASCII files usually show 0x20 there instead."
        )
    return None


def ebcdic_preview(data: bytes, codec: str = "cp037", *, limit: int = 1500) -> str:
    return data[:limit].decode(codec, errors="replace")


def extract_strings(data: bytes, *, min_len: int = 4, needle: str = "", limit: int = 80) -> list[str]:
    found = [match.decode("ascii") for match in re.findall(rb"[\x20-\x7e]{%d,}" % min_len, data)]
    if needle.strip():
        token = needle.strip().lower()
        found = [line for line in found if token in line.lower()]
    return found[:limit]


def render_report(data: bytes, *, name: str = "paste", needle: str = "SKY-") -> str:
    """Plain-text report for the File ID tab."""
    lines = [f"Name: {name}", f"Size: {len(data)} bytes shown to the identifier"]
    hits = _hits(data)
    if hits:
        lines.append("")
        lines.append("Signature:")
        for hit in hits:
            lines.append(f"- {hit.label}")
            lines.append(f"  Next: {hit.next_step}")
    else:
        lines.append("")
        lines.append("Signature: no well-known header in the first bytes.")

    text = ""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = ""
    peeled = peel_base64(text) if text else None
    lines.append("")
    if peeled is None:
        lines.append("Base64: this does not look like a base64 file.")
    else:
        lines.append(f"Base64: yes. Peeled {len(peeled)} bytes. Save that peel before you trust the extension.")
        inner = _hits(peeled)
        if inner:
            lines.append("Peeled signature:")
            for hit in inner:
                lines.append(f"- {hit.label}")
                lines.append(f"  Next: {hit.next_step}")
        else:
            lines.append("Peeled signature: none of the built-in headers matched.")

    hint = ebcdic_hint(data if peeled is None else peeled)
    target = data if peeled is None else peeled
    lines.append("")
    if hint:
        lines.append("EBCDIC hint: " + hint)
        lines.append("CP037 preview:")
        lines.append(ebcdic_preview(target))
    else:
        lines.append("EBCDIC hint: the repeating 0x40 space pattern is not strong here.")

    lines.append("")
    lines.append("Hex (first 256 bytes of the original):")
    lines.append(hex_dump(data))

    strings = extract_strings(target, needle=needle)
    lines.append("")
    if needle.strip():
        lines.append(f"ASCII strings containing {needle.strip()!r}:")
    else:
        lines.append("ASCII strings:")
    if strings:
        lines.extend(strings)
    else:
        lines.append("(none)")
    return "\n".join(lines)
