"""
Flexible number-list parsing for ASCII / decimal / hex / binary inputs.

Accepts common list shapes people paste from scripts, CTF writeups, and notes:
  [72, 84, 66, 123]
  72 84 66 123
  72,84,66,123
  72; 84; 66; 123
  (72 84 66)
  0x48 0x54 0x42
  \\x48\\x54\\x42
  01001000 01010100
  python-style assignments (strips comments and left-hand side)
"""

from __future__ import annotations

import re
from typing import Literal

NumberBase = Literal["auto", "dec", "hex", "bin", "oct"]


def strip_assignment_and_comments(text: str) -> str:
    """Remove Python-style assignments and # comments so raw lists parse cleanly.

    If a full line is commented but still holds number data (common when pasting
    from a disabled code block), keep the numbers after the #.
    """
    lines: list[str] = []
    for line in text.splitlines():
        if "#" in line:
            before, _, after = line.partition("#")
            # e.g. "    # 72, 84, 66" → keep the number tail
            if not before.strip() and re.search(r"\d", after):
                line = after
            else:
                line = before
        lines.append(line)
    text = "\n".join(lines)

    # ascii_values = [ ... ]  or  data = ( ... )
    m = re.search(r"=\s*([\[\(\{].*)", text, flags=re.DOTALL)
    if m:
        text = m.group(1)
    return text.strip()


def detect_list_format(text: str) -> str:
    """Human-readable guess of how the list is formatted."""
    raw = text.strip()
    if not raw:
        return "empty"
    if re.search(r"\\x[0-9a-fA-F]{2}", raw):
        return "escaped hex (\\xNN)"
    if re.search(r"\b0x[0-9a-fA-F]+\b", raw, re.I):
        return "hex with 0x prefix"
    if re.search(r"\b[01]{7,8}(?:\s+[01]{7,8})+\b", raw):
        return "binary groups"
    if "[" in raw or "]" in raw:
        return "bracketed list"
    if "(" in raw or ")" in raw:
        return "parenthesized list"
    if "," in raw:
        return "comma-separated"
    if ";" in raw:
        return "semicolon-separated"
    if re.search(r"\s+", raw):
        return "space-separated"
    return "single value / other"


def _tokenize(chunk: str, preferred: NumberBase) -> int | None:
    chunk = chunk.strip().strip(",")
    if not chunk:
        return None

    # 0xHH / 0bBB / 0oOO
    if re.fullmatch(r"0[xX][0-9a-fA-F]+", chunk):
        return int(chunk, 16)
    if re.fullmatch(r"0[bB][01]+", chunk):
        return int(chunk, 2)
    if re.fullmatch(r"0[oO][0-7]+", chunk):
        return int(chunk, 8)

    # \xHH (single token)
    m = re.fullmatch(r"\\x([0-9a-fA-F]{2})", chunk, re.I)
    if m:
        return int(m.group(1), 16)

    # Forced base
    if preferred == "hex":
        cleaned = chunk.replace("0x", "").replace("0X", "")
        if re.fullmatch(r"[0-9a-fA-F]+", cleaned):
            return int(cleaned, 16)
        return None
    if preferred == "bin":
        cleaned = chunk.replace("0b", "").replace("0B", "")
        if re.fullmatch(r"[01]+", cleaned):
            return int(cleaned, 2)
        return None
    if preferred == "oct":
        cleaned = chunk.replace("0o", "").replace("0O", "")
        if re.fullmatch(r"[0-7]+", cleaned):
            return int(cleaned, 8)
        return None
    if preferred == "dec":
        if re.fullmatch(r"-?\d+", chunk):
            return int(chunk, 10)
        return None

    # auto: decimal first, then hex if pure hex letters
    if re.fullmatch(r"-?\d+", chunk):
        return int(chunk, 10)
    if re.fullmatch(r"[0-9a-fA-F]+", chunk) and re.search(r"[a-fA-F]", chunk):
        return int(chunk, 16)
    return None


def parse_number_list(
    text: str,
    *,
    base: NumberBase = "auto",
) -> tuple[list[int], str | None]:
    """
    Parse a free-form number list into integers.

    Returns (numbers, error_message). error_message is None on success
    (empty input returns ([], None)).
    """
    if text is None:
        return [], None

    cleaned = strip_assignment_and_comments(text)
    if not cleaned:
        return [], None

    # Collapsed \\xHH\\xHH streams
    if re.search(r"\\x[0-9a-fA-F]{2}", cleaned, re.I):
        hex_bytes = re.findall(r"\\x([0-9a-fA-F]{2})", cleaned, re.I)
        if hex_bytes:
            return [int(h, 16) for h in hex_bytes], None

    # Normalize wrappers
    cleaned = cleaned.strip()
    # Drop outer brackets/braces/parens repeatedly
    for _ in range(3):
        if len(cleaned) >= 2 and cleaned[0] in "[({" and cleaned[-1] in "])}":
            cleaned = cleaned[1:-1].strip()

    # Split on common separators: comma, semicolon, whitespace, pipe, slash
    parts = re.split(r"[,;\s|/+]+", cleaned)
    numbers: list[int] = []
    bad: list[str] = []

    for part in parts:
        part = part.strip().strip("'\"")
        if not part:
            continue
        # trailing/leading brackets left on tokens
        part = part.strip("[](){}")
        if not part:
            continue
        val = _tokenize(part, base)
        if val is None:
            bad.append(part)
        else:
            numbers.append(val)

    if bad and not numbers:
        return [], f"Could not parse tokens as numbers: {', '.join(bad[:8])}"
    if bad:
        return numbers, f"Skipped unparsed tokens: {', '.join(bad[:8])}"
    return numbers, None
