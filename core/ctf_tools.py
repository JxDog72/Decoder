"""Find local CTF tools and say when one is missing on this operating system."""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class ToolStatus:
    name: str
    installed: bool
    path: str
    detail: str


def probe(candidates: list[str], missing: str, *, which=shutil.which) -> ToolStatus:
    """Return the first candidate that is on PATH."""
    for name in candidates:
        found = which(name)
        if found:
            return ToolStatus(name, True, found, found)
    label = candidates[0]
    return ToolStatus(label, False, "", f"{label} is not installed. {missing}")


def file_tool(*, which=shutil.which) -> ToolStatus:
    if os.name == "nt":
        missing = (
            "The file command ships with Linux and macOS. "
            "Built-in signatures in this tab still run on Windows."
        )
    else:
        missing = "On Debian, Kali, or Parrot: sudo apt install file"
    return probe(["file"], missing, which=which)


def john_tool(*, which=shutil.which) -> ToolStatus:
    if os.name == "nt":
        missing = (
            "John the Ripper jumbo is a separate Windows build. "
            "Unzip it and put john.exe on PATH. Kali already includes john."
        )
    else:
        missing = "On Kali or Parrot john is usually installed. Otherwise: sudo apt install john"
    return probe(["john", "john.exe"], missing, which=which)


def hashcat_tool(*, which=shutil.which) -> ToolStatus:
    if os.name == "nt":
        missing = (
            "Hashcat has a Windows zip. Unzip it and put hashcat.exe on PATH. "
            "A GPU build belongs on the machine that will run the crack."
        )
    else:
        missing = "On Kali or Parrot: sudo apt install hashcat"
    return probe(["hashcat", "hashcat.exe"], missing, which=which)


def extractxmi_tool(*, which=shutil.which) -> ToolStatus:
    missing = (
        "Install it inside a virtual environment: "
        "python3 -m venv ~/xmi-venv && source ~/xmi-venv/bin/activate && "
        "python -m pip install xmi-reader. The command is extractxmi. "
        "On Windows, activate the venv with Scripts\\activate."
    )
    return probe(["extractxmi", "extractxmi.exe"], missing, which=which)


def wevtutil_tool(*, which=shutil.which) -> ToolStatus:
    if os.name != "nt":
        return ToolStatus(
            "wevtutil",
            False,
            "",
            "wevtutil is not installed. It is a Windows command. "
            "On Linux, chainsaw or hayabusa can read an .evtx if you install one.",
        )
    return probe(["wevtutil", "wevtutil.exe"], "It ships with Windows. Check PATH.", which=which)


def run_file_description(path: str, *, which=shutil.which, timeout: float = 5) -> str:
    """One line from the system file command, or a not-installed note."""
    status = file_tool(which=which)
    if not status.installed:
        return status.detail
    try:
        done = subprocess.run(
            [status.path, "-b", path],
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"file did not finish: {exc}"
    line = (done.stdout or done.stderr or "").strip()
    return line or "file returned no description"


def quiet_popen(argv: list[str], cwd: str) -> subprocess.Popen[str]:
    """Start a command with no shell and no extra console window."""
    flags = 0
    if os.name == "nt":
        flags = subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]
    return subprocess.Popen(
        argv,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        text=True,
        shell=False,
        creationflags=flags,
    )
