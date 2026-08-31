"""Encode / decode helpers used by the Decoder GUI."""

from __future__ import annotations

import base64
import binascii
import html
import re
import urllib.parse
from typing import Iterable


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
    # ── ASCII / numbers ──────────────────────────────────────────────

    @staticmethod
    def numbers_to_text(nums: Iterable[int], *, encoding: str = "latin-1") -> str:
        data = bytes(n & 0xFF for n in nums)
        return data.decode(encoding, errors="replace")

    @staticmethod
    def text_to_numbers(text: str, *, encoding: str = "utf-8") -> list[int]:
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
        raw = text.encode(encoding, errors="replace")
        if sep == "":
            return raw.hex()
        return sep.join(f"{b:02x}" for b in raw)

    @staticmethod
    def hex_to_text(hex_str: str, *, encoding: str = "utf-8") -> str:
        cleaned = re.sub(r"[^0-9a-fA-F]", "", hex_str)
        if len(cleaned) % 2:
            cleaned = "0" + cleaned
        raw = bytes.fromhex(cleaned)
        return raw.decode(encoding, errors="replace")

    # ── Binary ───────────────────────────────────────────────────────

    @staticmethod
    def text_to_binary(text: str, *, encoding: str = "utf-8", group: bool = True) -> str:
        raw = text.encode(encoding, errors="replace")
        bits = [f"{b:08b}" for b in raw]
        return " ".join(bits) if group else "".join(bits)

    @staticmethod
    def binary_to_text(bin_str: str, *, encoding: str = "utf-8") -> str:
        cleaned = re.sub(r"[^01]", "", bin_str)
        if not cleaned:
            return ""
        # pad left to multiple of 8
        if len(cleaned) % 8:
            cleaned = cleaned.zfill(len(cleaned) + (8 - len(cleaned) % 8))
        raw = bytes(int(cleaned[i : i + 8], 2) for i in range(0, len(cleaned), 8))
        return raw.decode(encoding, errors="replace")

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
        return raw.decode(encoding, errors="replace")

    @staticmethod
    def b32_encode(text: str, *, encoding: str = "utf-8") -> str:
        return base64.b32encode(text.encode(encoding, errors="replace")).decode("ascii")

    @staticmethod
    def b32_decode(text: str, *, encoding: str = "utf-8") -> str:
        s = re.sub(r"\s+", "", text).upper()
        pad = (-len(s)) % 8
        s = s + ("=" * pad)
        return base64.b32decode(s).decode(encoding, errors="replace")

    @staticmethod
    def b85_encode(text: str, *, encoding: str = "utf-8") -> str:
        return base64.b85encode(text.encode(encoding, errors="replace")).decode("ascii")

    @staticmethod
    def b85_decode(text: str, *, encoding: str = "utf-8") -> str:
        s = re.sub(r"\s+", "", text)
        return base64.b85decode(s).decode(encoding, errors="replace")

    @staticmethod
    def a85_encode(text: str, *, encoding: str = "utf-8") -> str:
        return base64.a85encode(text.encode(encoding, errors="replace")).decode("ascii")

    @staticmethod
    def a85_decode(text: str, *, encoding: str = "utf-8") -> str:
        s = re.sub(r"\s+", "", text)
        return base64.a85decode(s).decode(encoding, errors="replace")

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
            cleaned = re.sub(r"[^0-9a-fA-F]", "", key)
            if len(cleaned) % 2:
                cleaned = "0" + cleaned
            if not cleaned:
                raise ValueError("XOR hex key is empty")
            kbytes = bytes.fromhex(cleaned)
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
            cleaned = re.sub(r"[^0-9a-fA-F]", "", data)
            if len(cleaned) % 2:
                cleaned = "0" + cleaned
            raw = bytes.fromhex(cleaned) if cleaned else b""
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
