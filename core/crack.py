"""Identify a pasted hash and build John and Hashcat commands.

Commands are text until the Crack tab runs them. Archive extractors stay
as copy-paste lines so the app never reads the host password files.
"""

from __future__ import annotations

import re
import shutil
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class HashAlgo:
    label: str
    john: str
    hashcat: int
    hint: str


ALGOS: dict[str, HashAlgo] = {
    "RACF": HashAlgo(
        "RACF",
        "racf",
        8500,
        "IBM RACF. John wants one hash per line, usually $racf$*USER*DIGEST. "
        "A spaced EBCDIC dump makes John say no hashes were loaded until you clean it.",
    ),
    "MD5": HashAlgo("MD5", "raw-md5", 0, "32 hex digits. NTLM is the same length."),
    "NTLM": HashAlgo("NTLM", "nt", 1000, "32 hex digits. Windows NT hash, not raw MD5."),
    "SHA-1": HashAlgo("SHA-1", "raw-sha1", 100, "40 hex digits."),
    "SHA-256": HashAlgo("SHA-256", "raw-sha256", 1400, "64 hex digits."),
    "SHA-512": HashAlgo("SHA-512", "raw-sha512", 1700, "128 hex digits."),
    "md5crypt": HashAlgo("md5crypt", "md5crypt", 500, "Linux-style $1$ hash."),
    "sha256crypt": HashAlgo("sha256crypt", "sha256crypt", 7400, "Linux-style $5$ hash."),
    "sha512crypt": HashAlgo("sha512crypt", "sha512crypt", 1800, "Linux-style $6$ hash. Common in /etc/shadow copies."),
    "bcrypt": HashAlgo("bcrypt", "bcrypt", 3200, "$2a$ / $2b$ / $2y$. Slow. Use a small wordlist."),
    "NetNTLMv2": HashAlgo("NetNTLMv2", "netntlmv2", 5600, "user::domain:challenge:proof:blob on one line."),
    "Kerberos TGS": HashAlgo("Kerberos TGS", "krb5tgs", 13100, "$krb5tgs$ ticket hash."),
    "Kerberos AS-REP": HashAlgo("Kerberos AS-REP", "krb5asrep", 18200, "$krb5asrep$ hash."),
}

AMBIGUOUS_32 = (
    "32 hex digits match both MD5 (hashcat -m 0, john --format=raw-md5) "
    "and NTLM (hashcat -m 1000, john --format=nt). The challenge wording says which."
)

_DOLLAR = re.compile(r"\$[^\s]{8,}")
_HEX = re.compile(r"\b[A-Fa-f0-9]{32}\b|\b[A-Fa-f0-9]{40}\b|\b[A-Fa-f0-9]{64}\b|\b[A-Fa-f0-9]{128}\b")
_NETNTLM = re.compile(r"\S+::\S*:[A-Fa-f0-9]{8,}:[A-Fa-f0-9]{16,}:\S+")


def clean_hashes(text: str) -> str:
    """Pull hash tokens out of a spaced or labeled dump, one per line."""
    found: list[str] = []
    seen: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        tokens: list[str] = []
        net = _NETNTLM.search(line)
        if net:
            tokens.append(net.group(0))
        tokens.extend(_DOLLAR.findall(line))
        if not tokens:
            tokens.extend(_HEX.findall(line))
        if not tokens and ":" in line and len(line) > 24:
            tokens.append(line)
        for token in tokens:
            if token not in seen:
                seen.add(token)
                found.append(token)
    return "\n".join(found)


def _label_for_token(token: str) -> str | None:
    lowered = token.lower()
    if lowered.startswith("$racf$"):
        return "RACF"
    if lowered.startswith(("$2a$", "$2b$", "$2y$")):
        return "bcrypt"
    if lowered.startswith("$6$"):
        return "sha512crypt"
    if lowered.startswith("$5$"):
        return "sha256crypt"
    if lowered.startswith("$1$"):
        return "md5crypt"
    if lowered.startswith("$krb5tgs$"):
        return "Kerberos TGS"
    if lowered.startswith("$krb5asrep$"):
        return "Kerberos AS-REP"
    if _NETNTLM.fullmatch(token):
        return "NetNTLMv2"
    hex_only = re.fullmatch(r"[A-Fa-f0-9]+", token)
    if not hex_only:
        return None
    return {
        32: "MD5",
        40: "SHA-1",
        64: "SHA-256",
        128: "SHA-512",
    }.get(len(token))


def identify_text(text: str) -> str:
    cleaned = clean_hashes(text)
    if not cleaned:
        return "No hash token found. Paste a hex digest, a $6$ hash, or a $racf$ line."
    lines = ["Cleaned hashes:", cleaned, ""]
    labels: list[str] = []
    ambiguous = False
    for token in cleaned.splitlines():
        label = _label_for_token(token)
        if label is None:
            lines.append(f"Unrecognized: {token[:80]}")
            continue
        if label not in labels:
            labels.append(label)
        if label == "MD5":
            ambiguous = True
        algo = ALGOS[label]
        lines.append(f"{label}: john --format={algo.john}    hashcat -m {algo.hashcat}")
        lines.append(algo.hint)
    if ambiguous:
        lines.append("")
        lines.append(AMBIGUOUS_32)
    return "\n".join(lines)


def detected_labels(text: str) -> list[str]:
    labels: list[str] = []
    for token in clean_hashes(text).splitlines():
        label = _label_for_token(token)
        if label and label not in labels:
            labels.append(label)
    return labels


def find_best64_rule(*, which=shutil.which) -> str | None:
    """Hashcat renamed best64.rule to best66.rule in 2025. Use whichever exists."""
    names = ("best64.rule", "best66.rule")
    roots: list[Path] = [
        Path("/usr/share/hashcat/rules"),
        Path("/usr/share/hashcat"),
    ]
    exe = which("hashcat") or which("hashcat.exe")
    if exe:
        folder = Path(exe).resolve().parent
        roots.extend([folder / "rules", folder])
    for root in roots:
        for name in names:
            candidate = root / name
            try:
                if candidate.is_file():
                    return str(candidate)
            except OSError:
                continue
    return None


def _quote(path: str) -> str:
    if any(char in path for char in " \t"):
        return '"' + path + '"'
    return path


def _show(argv: list[str]) -> str:
    shown: list[str] = []
    for part in argv:
        if part.startswith("--wordlist="):
            shown.append("--wordlist=" + _quote(part.split("=", 1)[1]))
        else:
            shown.append(_quote(part))
    return " ".join(shown)


@dataclass(frozen=True)
class BuiltCommand:
    argv: list[str] | None
    text: str
    runnable: bool
    reason: str


def build_commands(
    *,
    label: str,
    attack: str,
    wordlist: str,
    hash_name: str,
    mask: str,
    rule_path: str | None,
    john_installed: bool,
    hashcat_installed: bool,
) -> tuple[BuiltCommand, BuiltCommand]:
    """Build one John command and one Hashcat command."""
    algo = ALGOS[label]
    hashes = hash_name or "hashes.txt"
    word = wordlist.strip()
    mask_value = mask.strip() or "?d?d?d?d"
    notes = [
        f"# {algo.label}. {algo.hint}",
        "# Save the cleaned hashes as hashes.txt in the folder where you run this.",
        "# Stop the job if an NCL hash is still running after a few minutes. The type or the list is probably wrong.",
    ]
    if attack == "mask":
        notes.append("# ?l lower   ?u upper   ?d digit   ?s special   ?a all")
        notes.append("# A known prefix plus four digits looks like PREFIX?d?d?d?d")
        john_argv = ["john", f"--format={algo.john}", f"--mask={mask_value}", hashes]
        hash_argv = ["hashcat", "-m", str(algo.hashcat), "-a", "3", hashes, mask_value]
        need_list = False
    else:
        shown_list = word or "<wordlist>"
        john_argv = ["john", f"--format={algo.john}", f"--wordlist={shown_list}", hashes]
        hash_argv = ["hashcat", "-m", str(algo.hashcat), "-a", "0", hashes, shown_list]
        if attack == "best64":
            john_argv.insert(3, "--rules=best64")
            rule = rule_path or "best64.rule"
            hash_argv.extend(["-r", rule])
            notes.append("# John jumbo: --rules=best64. If John rejects the name, try --rules=Wordlist.")
            if rule_path is None:
                notes.append("# Hashcat 7 calls the same idea best66.rule. This command uses best64.rule until a rules file is found.")
        need_list = True

    john_text = "\n".join(notes + [_show(john_argv)])
    hash_text = "\n".join(notes + [_show(hash_argv)])

    john_ok = john_installed
    hash_ok = hashcat_installed
    john_reason = ""
    hash_reason = ""
    if not john_installed:
        john_ok = False
        john_reason = "john is not installed"
    if not hashcat_installed:
        hash_ok = False
        hash_reason = "hashcat is not installed"
    if need_list and not word:
        john_ok = False
        hash_ok = False
        john_reason = john_reason or "pick a wordlist that exists on this machine"
        hash_reason = hash_reason or "pick a wordlist that exists on this machine"
    elif need_list and not Path(word).is_file():
        john_ok = False
        hash_ok = False
        john_reason = "wordlist path is not a file on this machine. Copy still works."
        hash_reason = john_reason

    return (
        BuiltCommand(john_argv if john_ok else None, john_text, john_ok, john_reason),
        BuiltCommand(hash_argv if hash_ok else None, hash_text, hash_ok, hash_reason),
    )


def extractor_sheet() -> str:
    return "\n".join(
        [
            "These write a hash file you then open in the box above. They are copy-only.",
            "Replace FILE with the challenge file. Do not point unshadow at this machine's /etc/shadow.",
            "",
            "zip2john FILE > zip.hash",
            "rar2john FILE > rar.hash",
            "pdf2john FILE > pdf.hash",
            "office2john FILE > office.hash",
            "ssh2john FILE > ssh.hash",
            "racf2john RACFDB > racf.hash",
            "unshadow passwd-copy shadow-copy > unshadowed.txt",
            "",
            "john --show hashes.txt",
            "",
            "On Windows these *2john helpers are missing unless you installed John jumbo and added its run folder to PATH.",
            "On Kali they live next to john.",
        ]
    )
