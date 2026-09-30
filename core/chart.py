"""Printable reference rows for the ASCII chart tab."""

from __future__ import annotations

import unicodedata

# Short labels for bytes that have no visible glyph.
SHORT = {
    0: "NUL",
    1: "SOH",
    2: "STX",
    3: "ETX",
    4: "EOT",
    5: "ENQ",
    6: "ACK",
    7: "BEL",
    8: "BS",
    9: "TAB",
    10: "LF",
    11: "VT",
    12: "FF",
    13: "CR",
    14: "SO",
    15: "SI",
    16: "DLE",
    17: "DC1",
    18: "DC2",
    19: "DC3",
    20: "DC4",
    21: "NAK",
    22: "SYN",
    23: "ETB",
    24: "CAN",
    25: "EM",
    26: "SUB",
    27: "ESC",
    28: "FS",
    29: "GS",
    30: "RS",
    31: "US",
    32: "SP",
    127: "DEL",
}

# Words people type when they don't remember the abbreviation.
ALIASES = {
    "null": 0,
    "nul": 0,
    "newline": 10,
    "linefeed": 10,
    "line feed": 10,
    "lf": 10,
    "return": 13,
    "carriage return": 13,
    "cr": 13,
    "tab": 9,
    "horizontal tab": 9,
    "space": 32,
    "del": 127,
    "delete": 127,
    "escape": 27,
    "esc": 27,
    "backspace": 8,
}


def _name(n: int) -> str:
    if n in SHORT and n != 32:
        try:
            official = unicodedata.name(chr(n))
        except ValueError:
            official = SHORT[n]
        return official
    if n == 32:
        return "SPACE"
    try:
        return unicodedata.name(chr(n))
    except ValueError:
        return f"U+{n:04X}"


def _glyph(n: int) -> str:
    if n in SHORT:
        return SHORT[n]
    if 128 <= n <= 159:
        return "·"
    return chr(n)


def _escape(n: int) -> str:
    special = {0: r"\0", 9: r"\t", 10: r"\n", 13: r"\r", 92: r"\\"}
    if n in special:
        return special[n]
    return f"\\x{n:02x}"


def chart_row(n: int) -> dict:
    return {
        "n": n,
        "dec": f"{n:3d}",
        "hex": f"0x{n:02X}",
        "oct": f"{n:03o}",
        "bin": f"{n:08b}",
        "esc": _escape(n),
        "glyph": _glyph(n),
        "name": _name(n),
    }


ROWS = [chart_row(n) for n in range(256)]

HEADER = (
    f"{'Dec':>3}  {'Hex':<4}  {'Oct':<3}  {'Binary':<8}  "
    f"{'Esc':<4}  {'Char':<4}  Name"
)


def format_row(row: dict) -> str:
    return (
        f"{row['dec']}  {row['hex']:<4}  {row['oct']:<3}  {row['bin']:<8}  "
        f"{row['esc']:<4}  {row['glyph']:<4}  {row['name']}"
    )


def format_byte(n: int) -> str:
    if not 0 <= n <= 255:
        return f"{n} is outside a single byte (0–255)"
    return format_row(ROWS[n])


def lookup(query: str, *, full_range: bool = False) -> str:
    """Search the chart. Empty query returns the visible range."""
    q = (query or "").strip()
    visible = ROWS if full_range else [row for row in ROWS if 32 <= row["n"] <= 126]
    if not q:
        lines = [HEADER, ""]
        lines.extend(format_row(row) for row in visible)
        return "\n".join(lines)

    key = q.lower()
    if key in ALIASES:
        return _block([f"Name  {q}", format_byte(ALIASES[key])])

    if key.startswith("0x") or key.startswith("\\x"):
        return _from_hex(q)

    if key.startswith("0b"):
        return _from_bits(q[2:])

    if key.startswith("&#x") and q.endswith(";"):
        return _from_hex(q[3:-1])
    if key.startswith("&#") and q.endswith(";") and q[2:-1].isdigit():
        return _block([f"HTML entity  {q}", format_byte(int(q[2:-1]))])

    if len(q) == 1 and not q.isdigit():
        code = ord(q)
        if code > 255:
            return f"U+{code:04X}  {q}  is above a single byte"
        return _block([f"Character {q!r}", format_byte(code)])

    if re_full_digits(q):
        return _from_decimal_digits(q)

    if _is_hex_token(q) and any(c in "abcdefABCDEF" for c in q):
        return _from_hex(q)

    # A word such as "latin" or "digit": match names.
    if len(q) >= 3 and q.replace(" ", "").replace("-", "").isalpha():
        hits = [row for row in ROWS if key in row["name"].lower() or key == row["glyph"].lower()]
        if hits:
            body = [HEADER, ""]
            body.extend(format_row(row) for row in hits[:40])
            if len(hits) > 40:
                body.append(f"… {len(hits) - 40} more")
            return "\n".join(body)

    lines = [f"Each character in {q!r}", HEADER, ""]
    for ch in q:
        lines.append(format_byte(ord(ch)) if ord(ch) <= 255 else f"U+{ord(ch):04X}  {ch}  (above byte range)")
    return "\n".join(lines)


def re_full_digits(text: str) -> bool:
    return bool(text) and all("0" <= c <= "9" for c in text)


def _is_hex_token(text: str) -> bool:
    return bool(text) and all(c in "0123456789abcdefABCDEF" for c in text)


def _block(lines: list[str]) -> str:
    return "\n".join([lines[0], "", HEADER, "", *lines[1:]])


def _from_decimal_digits(q: str) -> str:
    n = int(q)
    lines = [f"As decimal {q}"]
    if 0 <= n <= 255:
        lines.append(format_byte(n))
    else:
        lines.append(f"{q} is outside a single byte (0–255)")
    if _is_hex_token(q) and not (len(q) > 1 and q[0] == "0" and int(q, 16) == n):
        hex_n = int(q, 16)
        if hex_n != n and 0 <= hex_n <= 255:
            lines.append("")
            lines.append(f"As hex 0x{q.upper()}")
            lines.append(format_byte(hex_n))
        elif len(q) >= 2 and len(q) % 2 == 0 and hex_n > 255:
            lines.append("")
            lines.append(f"As hex bytes 0x{q.upper()}")
            lines.extend(format_byte(int(q[i : i + 2], 16)) for i in range(0, len(q), 2))
    if len(q) == 1:
        lines.append("")
        lines.append(f"As the character {q!r}")
        lines.append(format_byte(ord(q)))
    return "\n".join([lines[0], "", HEADER, "", *lines[1:]])


def _from_hex(q: str) -> str:
    digits = q.lower().replace("0x", "").replace("\\x", "").replace(" ", "")
    digits = "".join(c for c in digits if c in "0123456789abcdef")
    if not digits:
        return "No hex digits in that lookup."
    if len(digits) <= 2:
        return _block([f"Hex 0x{digits.upper()}", format_byte(int(digits, 16))])
    if len(digits) % 2:
        return (
            f"Odd number of hex digits ({len(digits)}). "
            "Add the missing nibble or look up one byte."
        )
    lines = [f"Hex bytes 0x{digits.upper()}", "", HEADER, ""]
    lines.extend(format_byte(int(digits[i : i + 2], 16)) for i in range(0, len(digits), 2))
    return "\n".join(lines)


def _from_bits(bits: str) -> str:
    cleaned = "".join(c for c in bits if c in "01")
    if not cleaned:
        return "No binary digits in that lookup."
    if len(cleaned) <= 8:
        return _block([f"Binary {cleaned}", format_byte(int(cleaned, 2))])
    if len(cleaned) % 8:
        return f"Binary is {len(cleaned)} bits, not a whole number of bytes."
    lines = [f"Binary bytes", "", HEADER, ""]
    lines.extend(
        format_byte(int(cleaned[i : i + 8], 2)) for i in range(0, len(cleaned), 8)
    )
    return "\n".join(lines)
