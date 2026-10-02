"""Encode / decode helpers used by the Decoder GUI."""

from __future__ import annotations

import base64
import binascii
import html
import re
import urllib.parse
from typing import Iterable


def parse_hex_bytes(text: str) -> bytes:
    """Turn common hex spellings into bytes.

    Accepts spaced hex, compact hex, ``0x`` prefixes, ``\\xNN`` escapes,
    colon-separated bytes, and a pasted hex dump (address column ignored).
    An odd nibble count raises instead of padding a byte onto the front.
    """
    if text is None:
        return b""
    raw = text.strip()
    if not raw:
        return b""

    if re.search(r"\\x[0-9a-fA-F]{2}", raw):
        parts = re.findall(r"\\x([0-9a-fA-F]{2})", raw)
        if parts:
            return bytes(int(p, 16) for p in parts)

    dumped = _parse_hexdump(raw)
    if dumped is not None:
        return dumped

    # Drop 0x prefixes first so the leading 0 is not kept as a hex digit.
    stripped = re.sub(r"0[xX](?=[0-9a-fA-F])", "", raw)
    cleaned = re.sub(r"[^0-9a-fA-F]", "", stripped)
    if not cleaned:
        raise ValueError("No hex digits found")
    if len(cleaned) % 2:
        raise ValueError(
            f"Odd number of hex digits ({len(cleaned)}). "
            "Nothing was padded, so an extra byte was not added."
        )
    return bytes.fromhex(cleaned)


def _parse_hexdump(text: str) -> bytes | None:
    """Parse xxd / hexdump lines. Returns None when the text is not a dump."""
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if not lines:
        return None
    row_re = re.compile(
        r"^\s*[0-9a-fA-F]{4,16}\s*[:|]\s+"
        r"((?:[0-9a-fA-F]{2}\s+){1,24}[0-9a-fA-F]{2})\s*$"
    )
    # xxd also uses "offset  bytes" with no colon, but then the offset is 8 digits
    # followed by two spaces so it is not a normal spaced-hex string.
    xxd_re = re.compile(
        r"^\s*[0-9a-fA-F]{4,16}\s{2,}"
        r"((?:[0-9a-fA-F]{2}\s+){1,24}[0-9a-fA-F]{2})\s*$"
    )
    rows: list[int] = []
    for line in lines:
        core = line.split("|", 1)[0].rstrip()
        match = row_re.match(core) or xxd_re.match(core)
        if not match:
            return None
        rows.extend(int(byte, 16) for byte in match.group(1).split())
    return bytes(rows)


def parse_binary_bytes(text: str) -> bytes:
    """Turn binary text into bytes without padding an extra leading byte.

    Space-separated groups of 1–8 bits are each one byte (7-bit ASCII works).
    A continuous bit string must already be a whole number of bytes.
    """
    if text is None:
        return b""
    raw = text.strip()
    if not raw:
        return b""
    raw = re.sub(r"0[bB](?=[01])", "", raw)
    groups = re.findall(r"[01]+", raw)
    if not groups:
        raise ValueError("No binary digits found")
    if all(1 <= len(group) <= 8 for group in groups):
        return bytes(int(group, 2) for group in groups)
    bits = "".join(groups)
    if len(bits) % 8:
        raise ValueError(
            f"Binary is {len(bits)} bits, not a whole number of bytes. "
            "Separate each byte with spaces, or add the missing bits. "
            "Nothing was padded."
        )
    return bytes(int(bits[i : i + 8], 2) for i in range(0, len(bits), 8))


MORSE_TABLE = {
    "A": ".-",
    "B": "-...",
    "C": "-.-.",
    "D": "-..",
    "E": ".",
    "F": "..-.",
    "G": "--.",
    "H": "....",
    "I": "..",
    "J": ".---",
    "K": "-.-",
    "L": ".-..",
    "M": "--",
    "N": "-.",
    "O": "---",
    "P": ".--.",
    "Q": "--.-",
    "R": ".-.",
    "S": "...",
    "T": "-",
    "U": "..-",
    "V": "...-",
    "W": ".--",
    "X": "-..-",
    "Y": "-.--",
    "Z": "--..",
    "0": "-----",
    "1": ".----",
    "2": "..---",
    "3": "...--",
    "4": "....-",
    "5": ".....",
    "6": "-....",
    "7": "--...",
    "8": "---..",
    "9": "----.",
    ".": ".-.-.-",
    ",": "--..--",
    "?": "..--..",
    "'": ".----.",
    "!": "-.-.--",
    "/": "-..-.",
    "(": "-.--.",
    ")": "-.--.-",
    "&": ".-...",
    ":": "---...",
    ";": "-.-.-.",
    "=": "-...-",
    "+": ".-.-.",
    "-": "-....-",
    "_": "..--.-",
    '"': ".-..-.",
    "$": "...-..-",
    "@": ".--.-.",
    " ": "/",
}
MORSE_REVERSE = {v: k for k, v in MORSE_TABLE.items()}


class Converters:
    # Set by the latest conversion when a quiet choice was made (BOM, latin-1
    # fallback, a value outside 0–255). The GUI shows it in the status bar.
    last_note: str | None = None

    # ── ASCII / numbers ──────────────────────────────────────────────

    @staticmethod
    def numbers_to_text(nums: Iterable[int], *, encoding: str = "latin-1") -> str:
        values = list(nums)
        Converters.last_note = None
        if values and all(0 <= n <= 0x10FFFF for n in values) and any(n > 255 for n in values):
            Converters.last_note = "values above 255 were read as Unicode code points"
            return "".join(chr(n) for n in values)
        wrapped = [n for n in values if n < 0 or n > 255]
        raw = bytes(n & 0xFF for n in values)
        text, note = Converters.bytes_to_text(raw, encoding)
        if wrapped:
            extra = "values outside 0–255 were wrapped to their low byte"
            note = f"{extra}; {note}" if note else extra
        Converters.last_note = note
        return text

    @staticmethod
    def text_to_numbers(text: str, *, encoding: str = "utf-8") -> list[int]:
        Converters.last_note = None
        try:
            return list(text.encode(encoding))
        except UnicodeEncodeError:
            Converters.last_note = (
                f"some characters do not fit {encoding} and were replaced"
            )
            return list(text.encode(encoding, errors="replace"))

    @staticmethod
    def format_numbers(
        nums: Iterable[int],
        *,
        style: str = "comma",
        base: str = "dec",
    ) -> str:
        """style: comma | space | brackets | python | hex_escape"""
        nums = list(nums)

        def fmt(n: int) -> str:
            if base == "hex":
                return f"0x{n:02X}"
            if base == "bin":
                return f"0b{n:08b}"
            if base == "oct":
                return f"0o{n:o}"
            return str(n)

        if style == "hex_escape":
            return "".join(f"\\x{n:02x}" for n in nums)
        tokens = [fmt(n) for n in nums]
        if style == "space":
            return " ".join(tokens)
        if style == "brackets":
            return "[" + ", ".join(tokens) + "]"
        if style == "python":
            return "values = [" + ", ".join(tokens) + "]"
        return ", ".join(tokens)

    # ── Hex ──────────────────────────────────────────────────────────

    @staticmethod
    def text_to_hex(text: str, *, sep: str = " ", encoding: str = "utf-8") -> str:
        Converters.last_note = None
        raw = Converters._encode_text(text, encoding)
        if sep == "":
            return raw.hex()
        return sep.join(f"{b:02x}" for b in raw)

    @staticmethod
    def hex_to_text(hex_str: str, *, encoding: str = "utf-8") -> str:
        raw = parse_hex_bytes(hex_str)
        text, note = Converters.bytes_to_text(raw, encoding)
        Converters.last_note = note
        return text

    # ── Binary ───────────────────────────────────────────────────────

    @staticmethod
    def text_to_binary(text: str, *, encoding: str = "utf-8", group: bool = True) -> str:
        Converters.last_note = None
        raw = Converters._encode_text(text, encoding)
        bits = [f"{b:08b}" for b in raw]
        return " ".join(bits) if group else "".join(bits)

    @staticmethod
    def binary_to_text(bin_str: str, *, encoding: str = "utf-8") -> str:
        raw = parse_binary_bytes(bin_str)
        text, note = Converters.bytes_to_text(raw, encoding)
        Converters.last_note = note
        return text

    @staticmethod
    def binary_to_base64(bin_str: str) -> str:
        """Encode binary digits as the Base64 of those bytes."""
        raw = parse_binary_bytes(bin_str)
        Converters.last_note = f"{len(raw)} byte{'s' if len(raw) != 1 else ''} from binary"
        return base64.b64encode(raw).decode("ascii")

    @staticmethod
    def base64_to_binary(text: str) -> str:
        """Decode Base64 and show the bytes as spaced 8-bit groups."""
        compact = re.sub(r"\s+", "", text.strip())
        pad = (-len(compact)) % 4
        raw = base64.b64decode(compact + ("=" * pad), validate=False)
        Converters.last_note = f"{len(raw)} byte{'s' if len(raw) != 1 else ''} from Base64"
        return " ".join(f"{byte:08b}" for byte in raw)

    @staticmethod
    def _encode_text(text: str, encoding: str) -> bytes:
        try:
            return text.encode(encoding)
        except UnicodeEncodeError:
            Converters.last_note = (
                f"some characters do not fit {encoding} and were replaced"
            )
            return text.encode(encoding, errors="replace")

    @staticmethod
    def bytes_to_text(raw: bytes, encoding: str = "utf-8") -> tuple[str, str | None]:
        """Decode bytes without inserting U+FFFD for invalid UTF-8.

        Invalid UTF-8 is shown as latin-1 so every input byte stays one
        character. A leading UTF-8 BOM is removed and reported.
        """
        enc = (encoding or "utf-8").lower().replace("_", "-")
        if enc in ("latin-1", "latin1", "iso-8859-1", "byte", "bytes"):
            return raw.decode("latin-1"), Converters._byte_notes(raw.decode("latin-1"))
        if enc == "ascii":
            try:
                text = raw.decode("ascii")
            except UnicodeDecodeError:
                text = raw.decode("latin-1")
                return text, "not pure ASCII; each byte was kept as latin-1"
            return text, Converters._byte_notes(text)
        if raw.startswith(b"\xef\xbb\xbf"):
            try:
                text = raw.decode("utf-8-sig")
            except UnicodeDecodeError:
                text = raw.decode("latin-1")
                return text, "invalid UTF-8, so each byte was kept as latin-1"
            note = Converters._byte_notes(text)
            bom = "stripped a leading UTF-8 BOM"
            return text, f"{bom}; {note}" if note else bom
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = raw.decode("latin-1")
            note = "invalid UTF-8, so each byte was kept as latin-1"
            extra = Converters._byte_notes(text)
            return text, f"{note}; {extra}" if extra else note
        return text, Converters._byte_notes(text)

    @staticmethod
    def _byte_notes(text: str) -> str | None:
        notes: list[str] = []
        nuls = text.count("\x00")
        if nuls:
            notes.append(f"{nuls} NUL byte{'s' if nuls != 1 else ''} kept")
        return "; ".join(notes) if notes else None

    # ── Base64 / Base32 / Base85 ─────────────────────────────────────

    @staticmethod
    def b64_encode(text: str, *, encoding: str = "utf-8", urlsafe: bool = False) -> str:
        raw = text.encode(encoding, errors="replace")
        enc = base64.urlsafe_b64encode if urlsafe else base64.b64encode
        return enc(raw).decode("ascii")

    @staticmethod
    def b64_decode(text: str, *, encoding: str = "utf-8", urlsafe: bool = False) -> str:
        s = re.sub(r"\s+", "", text)
        # fix padding
        pad = (-len(s)) % 4
        s = s + ("=" * pad)
        dec = base64.urlsafe_b64decode if urlsafe else base64.b64decode
        raw = dec(s, validate=False)
        text, note = Converters.bytes_to_text(raw, encoding)
        Converters.last_note = note
        return text

    @staticmethod
    def b32_encode(text: str, *, encoding: str = "utf-8") -> str:
        return base64.b32encode(text.encode(encoding, errors="replace")).decode("ascii")

    @staticmethod
    def b32_decode(text: str, *, encoding: str = "utf-8") -> str:
        s = re.sub(r"\s+", "", text).upper()
        pad = (-len(s)) % 8
        s = s + ("=" * pad)
        text, note = Converters.bytes_to_text(base64.b32decode(s), encoding)
        Converters.last_note = note
        return text

    @staticmethod
    def b85_encode(text: str, *, encoding: str = "utf-8") -> str:
        return base64.b85encode(text.encode(encoding, errors="replace")).decode("ascii")

    @staticmethod
    def b85_decode(text: str, *, encoding: str = "utf-8") -> str:
        s = re.sub(r"\s+", "", text)
        text, note = Converters.bytes_to_text(base64.b85decode(s), encoding)
        Converters.last_note = note
        return text

    @staticmethod
    def a85_encode(text: str, *, encoding: str = "utf-8") -> str:
        return base64.a85encode(text.encode(encoding, errors="replace")).decode("ascii")

    @staticmethod
    def a85_decode(text: str, *, encoding: str = "utf-8") -> str:
        s = re.sub(r"\s+", "", text)
        text, note = Converters.bytes_to_text(base64.a85decode(s), encoding)
        Converters.last_note = note
        return text

    # ── URL ──────────────────────────────────────────────────────────

    @staticmethod
    def url_encode(text: str, *, quote_plus: bool = True) -> str:
        return urllib.parse.quote_plus(text) if quote_plus else urllib.parse.quote(text)

    @staticmethod
    def url_decode(text: str) -> str:
        return urllib.parse.unquote_plus(text)

    # ── HTML ─────────────────────────────────────────────────────────

    @staticmethod
    def html_encode(text: str) -> str:
        return html.escape(text, quote=True)

    @staticmethod
    def html_decode(text: str) -> str:
        return html.unescape(text)

    # ── Ciphers / transforms ─────────────────────────────────────────

    @staticmethod
    def rot_n(text: str, n: int = 13) -> str:
        n = n % 26
        out: list[str] = []
        for ch in text:
            if "a" <= ch <= "z":
                out.append(chr((ord(ch) - 97 + n) % 26 + 97))
            elif "A" <= ch <= "Z":
                out.append(chr((ord(ch) - 65 + n) % 26 + 65))
            else:
                out.append(ch)
        return "".join(out)

    @staticmethod
    def rot47(text: str) -> str:
        """ROT47 — rotate printable ASCII 33–126 by 47 (self-inverse)."""
        out: list[str] = []
        for ch in text:
            o = ord(ch)
            if 33 <= o <= 126:
                out.append(chr(33 + ((o - 33 + 47) % 94)))
            else:
                out.append(ch)
        return "".join(out)

    @staticmethod
    def atbash(text: str) -> str:
        """Atbash — A↔Z, B↔Y, … (self-inverse)."""
        out: list[str] = []
        for ch in text:
            if "a" <= ch <= "z":
                out.append(chr(ord("z") - (ord(ch) - ord("a"))))
            elif "A" <= ch <= "Z":
                out.append(chr(ord("Z") - (ord(ch) - ord("A"))))
            else:
                out.append(ch)
        return "".join(out)

    @staticmethod
    def vigenere(text: str, key: str, *, decrypt: bool = False) -> str:
        if not key:
            raise ValueError("Vigenère needs a key (letters)")
        key_letters = [c.lower() for c in key if c.isalpha()]
        if not key_letters:
            raise ValueError("Vigenère key must contain at least one letter")
        out: list[str] = []
        ki = 0
        for ch in text:
            if ch.isalpha():
                base = ord("A") if ch.isupper() else ord("a")
                shift = ord(key_letters[ki % len(key_letters)]) - ord("a")
                if decrypt:
                    shift = -shift
                out.append(chr((ord(ch) - base + shift) % 26 + base))
                ki += 1
            else:
                out.append(ch)
        return "".join(out)

    @staticmethod
    def xor_crypt(
        text: str,
        key: str,
        *,
        key_is_hex: bool = False,
        output: str = "text",
    ) -> str:
        """
        XOR text with a repeating key.
        output: text | hex | base64
        """
        if not key:
            raise ValueError("XOR needs a key")
        data = text.encode("utf-8", errors="replace")
        if key_is_hex:
            kbytes = parse_hex_bytes(key)
            if not kbytes:
                raise ValueError("XOR hex key is empty")
        else:
            kbytes = key.encode("utf-8", errors="replace")
        if not kbytes:
            raise ValueError("XOR key is empty")
        xored = bytes(b ^ kbytes[i % len(kbytes)] for i, b in enumerate(data))
        if output == "hex":
            return xored.hex()
        if output == "base64":
            return base64.b64encode(xored).decode("ascii")
        return xored.decode("utf-8", errors="replace")

    @staticmethod
    def xor_decrypt_from(
        data: str,
        key: str,
        *,
        key_is_hex: bool = False,
        input_fmt: str = "text",
    ) -> str:
        """Decrypt XOR payload that was stored as text, hex, or base64."""
        if input_fmt == "hex":
            raw = parse_hex_bytes(data)
            # feed as latin-1 so xor_crypt byte-ops work
            text = raw.decode("latin-1")
        elif input_fmt == "base64":
            s = re.sub(r"\s+", "", data)
            pad = (-len(s)) % 4
            raw = base64.b64decode(s + ("=" * pad))
            text = raw.decode("latin-1")
        else:
            text = data
        return Converters.xor_crypt(
            text, key, key_is_hex=key_is_hex, output="text"
        )

    @staticmethod
    def rail_fence_encrypt(text: str, rails: int = 3) -> str:
        if rails < 2:
            raise ValueError("Rail fence needs at least 2 rails")
        fence: list[list[str]] = [[] for _ in range(rails)]
        rail = 0
        direction = 1
        for ch in text:
            fence[rail].append(ch)
            rail += direction
            if rail == 0 or rail == rails - 1:
                direction *= -1
        return "".join("".join(row) for row in fence)

    @staticmethod
    def rail_fence_decrypt(cipher: str, rails: int = 3) -> str:
        if rails < 2:
            raise ValueError("Rail fence needs at least 2 rails")
        n = len(cipher)
        # mark zigzag path
        pattern = [0] * n
        rail = 0
        direction = 1
        for i in range(n):
            pattern[i] = rail
            rail += direction
            if rail == 0 or rail == rails - 1:
                direction *= -1
        counts = [pattern.count(r) for r in range(rails)]
        rows: list[list[str]] = []
        idx = 0
        for c in counts:
            rows.append(list(cipher[idx : idx + c]))
            idx += c
        pos = [0] * rails
        out: list[str] = []
        for r in pattern:
            out.append(rows[r][pos[r]])
            pos[r] += 1
        return "".join(out)

    @staticmethod
    def a1z26_encode(text: str) -> str:
        parts: list[str] = []
        for ch in text:
            if ch.isalpha():
                parts.append(str(ord(ch.upper()) - ord("A") + 1))
            elif ch == " ":
                parts.append("/")
            else:
                parts.append(ch)
        return " ".join(parts)

    @staticmethod
    def a1z26_decode(text: str) -> str:
        tokens = re.split(r"[\s,;]+", text.strip())
        out: list[str] = []
        for tok in tokens:
            if not tok:
                continue
            if tok == "/":
                out.append(" ")
            elif tok.isdigit():
                n = int(tok)
                if 1 <= n <= 26:
                    out.append(chr(ord("A") + n - 1))
                else:
                    out.append("?")
            else:
                out.append(tok)
        return "".join(out)

    @staticmethod
    def reverse_text(text: str) -> str:
        return text[::-1]

    @staticmethod
    def reverse_words(text: str) -> str:
        return " ".join(w[::-1] for w in text.split(" "))

    # ── Morse ────────────────────────────────────────────────────────

    @staticmethod
    def to_morse(text: str) -> str:
        parts: list[str] = []
        for ch in text.upper():
            if ch in MORSE_TABLE:
                parts.append(MORSE_TABLE[ch])
            elif ch == " ":
                parts.append("/")
            else:
                parts.append("?")
        return " ".join(parts)

    @staticmethod
    def from_morse(text: str) -> str:
        # normalize separators
        text = text.strip()
        text = re.sub(r"\s*/\s*", " / ", text)
        tokens = text.split()
        out: list[str] = []
        for tok in tokens:
            if tok == "/":
                out.append(" ")
            elif tok in MORSE_REVERSE:
                out.append(MORSE_REVERSE[tok])
            else:
                out.append("?")
        return "".join(out)

    # ── Unicode code points ──────────────────────────────────────────

    @staticmethod
    def text_to_codepoints(text: str, *, style: str = "U+") -> str:
        parts: list[str] = []
        for ch in text:
            cp = ord(ch)
            if style == "U+":
                parts.append(f"U+{cp:04X}")
            elif style == "\\u":
                if cp <= 0xFFFF:
                    parts.append(f"\\u{cp:04X}")
                else:
                    parts.append(f"\\U{cp:08X}")
            else:
                parts.append(str(cp))
        return " ".join(parts)

    @staticmethod
    def codepoints_to_text(text: str) -> str:
        # U+0041, \u0041, \U0001F600, decimal ordinals
        tokens = re.findall(
            r"U\+([0-9a-fA-F]{1,8})|\\u([0-9a-fA-F]{4})|\\U([0-9a-fA-F]{8})|\\x([0-9a-fA-F]{2})|\b(\d{1,7})\b",
            text,
        )
        chars: list[str] = []
        for u_plus, u4, u8, x2, dec in tokens:
            if u_plus:
                chars.append(chr(int(u_plus, 16)))
            elif u4:
                chars.append(chr(int(u4, 16)))
            elif u8:
                chars.append(chr(int(u8, 16)))
            elif x2:
                chars.append(chr(int(x2, 16)))
            elif dec:
                n = int(dec)
                if 0 <= n <= 0x10FFFF:
                    chars.append(chr(n))
        if chars:
            return "".join(chars)
        # fallback: treat whole input as unicode-escape
        try:
            return text.encode("utf-8").decode("unicode_escape")
        except Exception:
            return text

    # ── Hash digests (one-way) ────────────────────────────────────────

    HASH_ALGOS = (
        "md5",
        "sha1",
        "sha224",
        "sha256",
        "sha384",
        "sha512",
        "sha3_224",
        "sha3_256",
        "sha3_384",
        "sha3_512",
        "blake2b",
        "blake2s",
    )

    # hex digest length (chars) → likely algorithms
    HASH_LEN_HINTS: dict[int, tuple[str, ...]] = {
        32: ("md5", "md4"),
        40: ("sha1", "ripemd160"),
        56: ("sha224", "sha3_224"),
        64: ("sha256", "sha3_256", "blake2s"),
        96: ("sha384", "sha3_384"),
        128: ("sha512", "sha3_512", "blake2b"),
    }

    @staticmethod
    def _make_hasher(algo: str):
        import hashlib

        algo = algo.lower().replace("-", "_")
        aliases = {"sha3-256": "sha3_256", "sha3-512": "sha3_512"}
        algo = aliases.get(algo, algo)
        try:
            return hashlib.new(algo), algo
        except ValueError as e:
            raise ValueError(f"Unknown hash algorithm: {algo}") from e

    @staticmethod
    def hash_bytes(data: bytes, algo: str = "sha256") -> str:
        h, _ = Converters._make_hasher(algo)
        h.update(data)
        return h.hexdigest()

    @staticmethod
    def hash_text(text: str, algo: str = "md5", *, encoding: str = "utf-8") -> str:
        raw = text.encode(encoding, errors="replace")
        return Converters.hash_bytes(raw, algo)

    @staticmethod
    def hash_file(path: str, algo: str = "sha256", *, chunk_size: int = 1024 * 1024) -> str:
        """Stream-hash a file so large downloads don't need to fit in RAM."""
        h, _ = Converters._make_hasher(algo)
        with open(path, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()

    @staticmethod
    def hash_file_multi(
        path: str,
        algos: Iterable[str] | None = None,
        *,
        chunk_size: int = 1024 * 1024,
    ) -> dict[str, str]:
        """One-pass multi-algorithm file hash (efficient for big downloads)."""
        names = list(algos) if algos is not None else list(Converters.HASH_ALGOS)
        hashers: dict[str, object] = {}
        for a in names:
            try:
                h, canon = Converters._make_hasher(a)
                hashers[canon] = h
            except ValueError:
                continue
        if not hashers:
            raise ValueError("No usable hash algorithms")
        with open(path, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                for h in hashers.values():
                    h.update(chunk)  # type: ignore[attr-defined]
        return {name: h.hexdigest() for name, h in hashers.items()}  # type: ignore[attr-defined]

    @staticmethod
    def file_size_label(path: str) -> str:
        n = __import__("os").path.getsize(path)
        if n < 1024:
            return f"{n} B"
        if n < 1024 * 1024:
            return f"{n / 1024:.1f} KB"
        if n < 1024 * 1024 * 1024:
            return f"{n / (1024 * 1024):.2f} MB"
        return f"{n / (1024 * 1024 * 1024):.2f} GB"

    @staticmethod
    def normalize_hash(hex_str: str) -> str:
        s = (hex_str or "").strip()
        if not s:
            return ""
        s = re.sub(
            r"(?is)^\s*(checksum|digest|hash)?\s*"
            r"(md5|sha-?1|sha-?224|sha-?256|sha-?384|sha-?512|sha3[_-]?\d+|blake2[bs])"
            r"\s*(\([^)]*\))?\s*[:=]?\s*",
            "",
            s,
            count=1,
        )
        s = s.strip().strip("()[]\"'")
        if s.lower().startswith("0x"):
            s = s[2:]
        first = s.split()[0] if s.split() else s
        return re.sub(r"[^0-9a-fA-F]", "", first).lower()

    @staticmethod
    def looks_like_hash(text: str) -> bool:
        cleaned = Converters.normalize_hash(text)
        if not cleaned or not re.fullmatch(r"[0-9a-f]+", cleaned):
            return False
        return len(cleaned) in Converters.HASH_LEN_HINTS

    @staticmethod
    def guess_hash_algos(hex_digest: str) -> list[str]:
        cleaned = Converters.normalize_hash(hex_digest)
        if not cleaned or not re.fullmatch(r"[0-9a-f]+", cleaned):
            return []
        hints = Converters.HASH_LEN_HINTS.get(len(cleaned), ())
        return [a for a in hints if a in Converters.HASH_ALGOS or True]

    @staticmethod
    def _verify_digests(
        digests: dict[str, str],
        expected: str,
        algo: str = "auto",
    ) -> dict:
        expected_n = Converters.normalize_hash(expected)
        if not expected_n or not re.fullmatch(r"[0-9a-f]+", expected_n):
            raise ValueError("Expected hash must be a hex string")

        algo = (algo or "auto").lower()
        if algo != "auto":
            if algo not in digests:
                raise ValueError(f"No digest for algorithm: {algo}")
            computed = digests[algo]
            return {
                "match": computed.lower() == expected_n,
                "algo": algo,
                "computed": computed,
                "expected": expected_n,
                "tried": [algo],
            }

        # Prefer length-matching algos first
        order = list(Converters.guess_hash_algos(expected_n))
        for a in digests:
            if a not in order:
                order.append(a)

        tried: list[str] = []
        for a in order:
            if a not in digests:
                continue
            computed = digests[a]
            tried.append(a)
            if computed.lower() == expected_n:
                return {
                    "match": True,
                    "algo": a,
                    "computed": computed,
                    "expected": expected_n,
                    "tried": tried,
                }

        display_algo = order[0] if order and order[0] in digests else next(iter(digests), "unknown")
        return {
            "match": False,
            "algo": display_algo,
            "computed": digests.get(display_algo, ""),
            "expected": expected_n,
            "tried": tried,
        }

    @staticmethod
    def verify_hash(
        text: str,
        expected: str,
        algo: str = "auto",
        *,
        encoding: str = "utf-8",
    ) -> dict:
        """Compare text against an expected hex digest."""
        raw = text.encode(encoding, errors="replace")
        if algo != "auto" and (algo or "").lower() != "auto":
            digests = {(algo or "sha256").lower(): Converters.hash_bytes(raw, algo)}
        else:
            digests = Converters.hash_all_bytes(raw)
        return Converters._verify_digests(digests, expected, algo)

    @staticmethod
    def verify_file_hash(path: str, expected: str, algo: str = "auto") -> dict:
        """
        Stream-hash a file and compare to an expected hex digest.
        Ideal for verifying installer / download checksums.
        """
        if algo != "auto" and (algo or "").lower() != "auto":
            digests = {algo.lower(): Converters.hash_file(path, algo)}
        else:
            # one pass over the file for all algorithms
            digests = Converters.hash_file_multi(path)
        result = Converters._verify_digests(digests, expected, algo)
        result["path"] = path
        result["size"] = Converters.file_size_label(path)
        return result

    @staticmethod
    def hash_all_bytes(data: bytes) -> dict[str, str]:
        out: dict[str, str] = {}
        for algo in Converters.HASH_ALGOS:
            try:
                out[algo] = Converters.hash_bytes(data, algo)
            except ValueError:
                continue
        return out

    @staticmethod
    def hash_all(text: str, *, encoding: str = "utf-8") -> dict[str, str]:
        raw = text.encode(encoding, errors="replace")
        return Converters.hash_all_bytes(raw)

    # ── Bytes summary ────────────────────────────────────────────────

    @staticmethod
    def byte_summary(text: str, *, encoding: str = "utf-8") -> str:
        raw = text.encode(encoding, errors="replace")
        lines = [
            f"Characters : {len(text)}",
            f"Bytes ({encoding}): {len(raw)}",
            f"Hex        : {raw.hex()}",
            f"Base64     : {base64.b64encode(raw).decode('ascii')}",
            f"Decimal    : {', '.join(str(b) for b in raw)}",
        ]
        return "\n".join(lines)
