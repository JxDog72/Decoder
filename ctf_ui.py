"""File ID, Crack, and Wordlists for Decoder."""

from __future__ import annotations

import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog

import customtkinter as ctk

from core.crack import (
    ALGOS,
    build_commands,
    clean_hashes,
    detected_labels,
    extractor_sheet,
    find_best64_rule,
    identify_text,
)
from core.ctf_tools import (
    extractxmi_tool,
    hashcat_tool,
    john_tool,
    quiet_popen,
    run_file_description,
    wevtutil_tool,
)
from core.fileid import READ_LIMIT, ebcdic_preview, peel_base64, render_report
from core.wordlists import locate_wordlists, platform_note

ROOT = Path(__file__).resolve().parent
WORK = ROOT / ".ctf-work"


class CommandJob:
    """Run one local command and stream its output into a text pane."""

    def __init__(self, widget, pane, status):
        self.widget = widget
        self.pane = pane
        self.status = status
        self.proc = None

    def start(self, argv: list[str], cwd: str) -> None:
        if self.proc is not None and self.proc.poll() is None:
            self.status.set("A command is already running. Stop it first.", ok=False)
            return
        self.pane.set("$ " + " ".join(argv) + "\n")
        try:
            self.proc = quiet_popen(argv, cwd)
        except OSError as exc:
            self.status.set(f"Could not start: {exc}", ok=False)
            return
        threading.Thread(target=self._read, daemon=True).start()
        self.status.set("Running…", ok=True)

    def _read(self) -> None:
        proc = self.proc
        if proc is None or proc.stdout is None:
            return
        for line in proc.stdout:
            self.widget.after(0, lambda text=line: self._append(text))
        code = proc.wait()
        self.widget.after(0, lambda: self.status.set(f"Command finished ({code})", ok=code == 0))

    def _append(self, text: str) -> None:
        self.pane.set(self.pane.get() + text)

    def stop(self) -> None:
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            self.status.set("Stopped", ok=False)


def mount_ctf_tabs(status, file_tab, crack_tab, list_tab) -> None:
    """Fill the CTF tabs. Imported from app after the widgets exist."""
    from app import COLORS, ActionRow, TextPane, copy_to_clipboard, font_ui

    wordlist = tk.StringVar(value="")
    for tab in (file_tab, crack_tab, list_tab):
        tab.configure(fg_color=COLORS["bg"])

    FileIdTab(file_tab, status, TextPane, ActionRow, copy_to_clipboard, font_ui, COLORS).pack(
        fill="both", expand=True, padx=4, pady=4
    )
    CrackTab(
        crack_tab, status, wordlist, TextPane, ActionRow, copy_to_clipboard, font_ui, COLORS
    ).pack(fill="both", expand=True, padx=4, pady=4)
    WordlistTab(list_tab, status, wordlist, TextPane, ActionRow, font_ui, COLORS).pack(
        fill="both", expand=True, padx=4, pady=4
    )


class FileIdTab(ctk.CTkFrame):
    def __init__(self, master, status, TextPane, ActionRow, copy_to_clipboard, font_ui, colors, **kwargs):
        super().__init__(master, fg_color=colors["bg"], **kwargs)
        self.status = status
        self.copy_to_clipboard = copy_to_clipboard
        self.colors = colors
        self._path: str | None = None
        self._bytes = b""
        self.job = None

        ctk.CTkLabel(
            self,
            text=(
                "Drop a challenge file in here when the extension is a lie. "
                "This checks the header, peels a base64 layer, and flags EBCDIC "
                "(the repeating 0x40 from the Gibson XMI exercise). "
                "Windows event logs and registry hives are named here."
            ),
            text_color=colors["muted"],
            font=font_ui(12),
            wraplength=980,
            justify="left",
            anchor="w",
        ).pack(fill="x", pady=(0, 8))

        self.path_label = ctk.CTkLabel(
            self, text="No file selected. You can also paste below.",
            text_color=colors["muted"], font=font_ui(12), anchor="w",
        )
        self.path_label.pack(fill="x")

        row = ActionRow(self)
        row.pack(fill="x", pady=(8, 6))
        row.add_btn("Browse file…", self.browse)
        row.add_btn("Identify", self.identify, primary=True)
        row.add_btn("Save base64 peel", self.save_peel)
        row.add_btn("Save CP037 text", self.save_cp037)
        row.add_btn("Read EVTX", self.read_evtx)
        row.add_btn("extractxmi", self.run_extract)
        row.add_btn("Copy report", self.copy_report)
        row.add_btn("Stop", self.stop_job)

        needle_row = ctk.CTkFrame(self, fg_color="transparent")
        needle_row.pack(fill="x", pady=(0, 6))
        ctk.CTkLabel(needle_row, text="String filter", text_color=colors["muted"], font=font_ui(12)).pack(side="left")
        self.needle = ctk.CTkEntry(needle_row, width=160, fg_color=colors["input_bg"], border_color=colors["border"])
        self.needle.pack(side="left", padx=(8, 0))
        self.needle.insert(0, "SKY-")

        self.paste = TextPane(self, "Paste, if you do not have a file yet", height=90)
        self.paste.pack(fill="x", pady=(0, 6))
        self.report = TextPane(self, "What this file is", height=280)
        self.report.pack(fill="both", expand=True)
        self.job = CommandJob(self, self.report, self.status)

    def browse(self) -> None:
        path = filedialog.askopenfilename(title="Challenge file")
        if not path:
            return
        self._path = path
        self.path_label.configure(text=path, text_color=self.colors["accent"])
        self.status.set("File selected", ok=True, fmt=Path(path).name)

    def _load(self) -> bytes:
        if self._path:
            data = Path(self._path).read_bytes()
            self._bytes = data[:READ_LIMIT]
            return data
        text = self.paste.get()
        data = text.encode("utf-8")
        self._bytes = data
        return data

    def identify(self) -> None:
        try:
            data = self._load()
        except OSError as exc:
            self.status.set(f"Could not read the file: {exc}", ok=False)
            return
        shown = data[:READ_LIMIT]
        report = render_report(shown, name=Path(self._path).name if self._path else "paste", needle=self.needle.get())
        if len(data) > READ_LIMIT:
            report += f"\n\nOnly the first {READ_LIMIT} bytes were identified."
        if self._path:
            report += "\n\nfile command:\n" + run_file_description(self._path)
        self.report.set(report)
        self.status.set("Identified", ok=True)

    def _work_bytes(self) -> bytes:
        if not self._bytes:
            self._load()
        try:
            text = self._bytes.decode("utf-8")
        except UnicodeDecodeError:
            return self._bytes
        peeled = peel_base64(text)
        return self._bytes if peeled is None else peeled

    def _dest(self, suffix: str) -> Path:
        WORK.mkdir(exist_ok=True)
        if self._path:
            return Path(self._path).with_name(Path(self._path).name + suffix)
        return WORK / ("paste" + suffix)

    def save_peel(self) -> None:
        try:
            raw = self._load()
        except OSError as exc:
            self.status.set(str(exc), ok=False)
            return
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            self.status.set("This file is not a base64 text peel.", ok=False)
            return
        peeled = peel_base64(text)
        if peeled is None:
            self.status.set("No base64 layer found.", ok=False)
            return
        dest = self._dest(".decoded")
        dest.write_bytes(peeled)
        self.status.set(f"Wrote {dest.name}", ok=True, fmt=str(dest))

    def save_cp037(self) -> None:
        try:
            self._load()
        except OSError as exc:
            self.status.set(str(exc), ok=False)
            return
        text = ebcdic_preview(self._work_bytes(), limit=len(self._work_bytes()) or 1)
        dest = self._dest(".cp037.txt")
        dest.write_text(text, encoding="utf-8")
        self.status.set(f"Wrote {dest.name}", ok=True, fmt=str(dest))

    def read_evtx(self) -> None:
        tool = wevtutil_tool()
        if not self._path:
            self.status.set("Browse to an .evtx first.", ok=False)
            return
        if not tool.installed:
            self.report.set(tool.detail)
            self.status.set("wevtutil is not installed", ok=False)
            return
        assert self.job is not None
        self.job.start([tool.path, "qe", self._path, "/lf:true", "/f:text", "/c:30"], str(Path(self._path).parent))

    def run_extract(self) -> None:
        tool = extractxmi_tool()
        if not self._path:
            self.status.set("Browse to the XMI file first.", ok=False)
            return
        if not tool.installed:
            self.report.set(tool.detail)
            self.status.set("extractxmi is not installed", ok=False)
            return
        assert self.job is not None
        self.job.start([tool.path, self._path], str(Path(self._path).parent))

    def copy_report(self) -> None:
        self.copy_to_clipboard(self, self.report.get())
        self.status.set("Report copied", ok=True)

    def stop_job(self) -> None:
        if self.job is not None:
            self.job.stop()


class CrackTab(ctk.CTkFrame):
    def __init__(self, master, status, wordlist, TextPane, ActionRow, copy_to_clipboard, font_ui, colors, **kwargs):
        super().__init__(master, fg_color=colors["bg"], **kwargs)
        self.status = status
        self.wordlist = wordlist
        self.copy_to_clipboard = copy_to_clipboard
        self._john = None
        self._hashcat = None

        ctk.CTkLabel(
            self,
            text=(
                "Paste hashes. Clean puts one token on each line. "
                "Build writes a John command and a Hashcat command you can copy into Kali. "
                "Run stays off with “tool not installed” until that program is on PATH. "
                "Wordlists come from the Wordlists tab. Archive helpers (*2john, unshadow) are copy-only."
            ),
            text_color=colors["muted"],
            font=font_ui(12),
            wraplength=980,
            justify="left",
            anchor="w",
        ).pack(fill="x", pady=(0, 8))

        self.tools = ctk.CTkLabel(self, text="", text_color=colors["muted"], font=font_ui(12), anchor="w")
        self.tools.pack(fill="x")

        self.hashes = TextPane(self, "Hashes", height=110)
        self.hashes.pack(fill="x", pady=(6, 6))

        row = ActionRow(self)
        row.pack(fill="x", pady=(0, 6))
        row.add_btn("Clean lines", self.clean)
        row.add_btn("Identify", self.identify, primary=True)
        self.format_var = row.add_option("Type", ["Auto", *ALGOS.keys()], "Auto", width=140)
        self.attack_var = row.add_option("Attack", ["dictionary", "best64", "mask"], "dictionary", width=120)
        row.add_btn("Build commands", self.build)
        row.add_btn("Copy John", self.copy_john)
        row.add_btn("Copy Hashcat", self.copy_hashcat)
        row.add_btn("Run John", self.run_john)
        row.add_btn("Run Hashcat", self.run_hashcat)
        row.add_btn("Stop", self.stop_job)
        row.add_btn("Extract helpers", self.show_extractors)

        mask_row = ctk.CTkFrame(self, fg_color="transparent")
        mask_row.pack(fill="x", pady=(0, 6))
        ctk.CTkLabel(
            mask_row,
            text="Mask   ?l lower  ?u upper  ?d digit  ?s special",
            text_color=colors["muted"],
            font=font_ui(12),
        ).pack(side="left")
        self.mask = ctk.CTkEntry(mask_row, width=280, fg_color=colors["input_bg"], border_color=colors["border"])
        self.mask.pack(side="left", padx=(8, 0))
        self.mask.insert(0, "PREFIX?d?d?d?d")

        self.commands = TextPane(self, "Commands", height=200)
        self.commands.pack(fill="both", expand=True)
        self.job = CommandJob(self, self.commands, self.status)
        self.refresh_tools()

    def refresh_tools(self) -> None:
        john = john_tool()
        cat = hashcat_tool()
        self.tools.configure(
            text=(
                f"john: {john.detail if not john.installed else john.path}"
                f"    hashcat: {cat.detail if not cat.installed else cat.path}"
            )
        )

    def clean(self) -> None:
        cleaned = clean_hashes(self.hashes.get())
        if not cleaned:
            self.status.set("No hash token found", ok=False)
            return
        self.hashes.set(cleaned)
        self.status.set(f"{cleaned.count(chr(10)) + 1} hash line(s)", ok=True)

    def identify(self) -> None:
        report = identify_text(self.hashes.get())
        self.commands.set(report)
        labels = detected_labels(self.hashes.get())
        if labels:
            self.format_var.set(labels[0])
        self.status.set("Hash check finished", ok=bool(labels))

    def _chosen_label(self) -> str | None:
        choice = self.format_var.get()
        if choice != "Auto":
            return choice
        labels = detected_labels(self.hashes.get())
        if not labels:
            self.status.set("Identify the hash first, or pick a type.", ok=False)
            return None
        return labels[0]

    def build(self) -> None:
        label = self._chosen_label()
        if label is None:
            return
        john = john_tool()
        cat = hashcat_tool()
        self._john, self._hashcat = build_commands(
            label=label,
            attack=self.attack_var.get(),
            wordlist=self.wordlist.get(),
            hash_name="hashes.txt",
            mask=self.mask.get(),
            rule_path=find_best64_rule(),
            john_installed=john.installed,
            hashcat_installed=cat.installed,
        )
        self.commands.set("JOHN\n" + self._john.text + "\n\nHASHCAT\n" + self._hashcat.text)
        if self._john.runnable or self._hashcat.runnable:
            self.status.set("Commands ready", ok=True)
        else:
            self.status.set(self._john.reason or self._hashcat.reason, ok=False)

    def copy_john(self) -> None:
        if self._john is None:
            self.build()
        if self._john is not None:
            self.copy_to_clipboard(self, self._john.text)
            self.status.set("John command copied", ok=True)

    def copy_hashcat(self) -> None:
        if self._hashcat is None:
            self.build()
        if self._hashcat is not None:
            self.copy_to_clipboard(self, self._hashcat.text)
            self.status.set("Hashcat command copied", ok=True)

    def _hash_file(self) -> Path | None:
        text = clean_hashes(self.hashes.get()) or self.hashes.get().strip()
        if not text:
            self.status.set("Paste a hash first.", ok=False)
            return None
        WORK.mkdir(exist_ok=True)
        dest = WORK / "hashes.txt"
        dest.write_text(text + "\n", encoding="utf-8")
        return dest

    def _launch(self, built, installed: bool) -> None:
        if built is None:
            self.build()
            return
        if not installed or not built.runnable or not built.argv:
            self.status.set(built.reason or "tool not installed", ok=False)
            return
        dest = self._hash_file()
        if dest is None:
            return
        argv = [str(dest) if part == "hashes.txt" else part for part in built.argv]
        self.job.start(argv, str(WORK))

    def run_john(self) -> None:
        self.refresh_tools()
        if self._john is None:
            self.build()
        self._launch(self._john, john_tool().installed)

    def run_hashcat(self) -> None:
        self.refresh_tools()
        if self._hashcat is None:
            self.build()
        self._launch(self._hashcat, hashcat_tool().installed)

    def stop_job(self) -> None:
        self.job.stop()

    def show_extractors(self) -> None:
        self.commands.set(extractor_sheet())
        self.status.set("Copy the helper you need. These are not run from the app.", ok=True)


class WordlistTab(ctk.CTkFrame):
    def __init__(self, master, status, wordlist, TextPane, ActionRow, font_ui, colors, **kwargs):
        super().__init__(master, fg_color=colors["bg"], **kwargs)
        self.status = status
        self.wordlist = wordlist
        self._hits = []

        ctk.CTkLabel(
            self,
            text=platform_note(),
            text_color=colors["muted"],
            font=font_ui(12),
            wraplength=980,
            justify="left",
            anchor="w",
        ).pack(fill="x", pady=(0, 8))

        row = ActionRow(self)
        row.pack(fill="x", pady=(0, 6))
        row.add_btn("Rescan", self.rescan, primary=True)
        row.add_btn("Browse to a list…", self.browse)
        self.menu = ctk.CTkOptionMenu(
            row,
            variable=wordlist,
            values=["(none found)"],
            width=460,
            height=30,
            fg_color=colors["btn"],
            button_color=colors["accent_dim"],
            button_hover_color=colors["accent"],
            dropdown_fg_color=colors["panel2"],
            font=font_ui(12),
        )
        row.adopt(self.menu)
        wordlist.set("(none found)")

        self.report = TextPane(self, "Lists on this machine", height=320)
        self.report.pack(fill="both", expand=True)
        self.rescan()

    def rescan(self) -> None:
        self._hits = locate_wordlists(app_dir=ROOT)
        ready = [hit.path for hit in self._hits if hit.kind == "ready"]
        values = ready or ["(none found)"]
        self.menu.configure(values=values)
        current = self.wordlist.get()
        if current not in values:
            self.wordlist.set(values[0])
        lines = [platform_note(), ""]
        if not self._hits:
            lines.append("No wordlist file was found.")
            lines.append("On Parrot or Kali, rockyou.txt is usually /usr/share/wordlists/rockyou.txt")
            lines.append("John also ships a short password.lst next to the program.")
            lines.append(r"On Windows, put a list in Decoder\wordlists or browse to one.")
        else:
            lines.append("The menu is the list the Crack tab will use.")
            for hit in self._hits:
                lines.append(f"[{hit.kind}] {hit.path}")
                lines.append(f"    {hit.note}")
        self.report.set("\n".join(lines))
        self.status.set(f"{len(ready)} wordlist(s) ready", ok=bool(ready))

    def browse(self) -> None:
        path = filedialog.askopenfilename(
            title="Wordlist",
            filetypes=[("Word lists", "*.txt *.lst *.dic"), ("All files", "*.*")],
        )
        if not path:
            return
        values = list(self.menu.cget("values"))
        if "(none found)" in values:
            values = []
        if path not in values:
            values.insert(0, path)
        self.menu.configure(values=values)
        self.wordlist.set(path)
        self.status.set("Wordlist selected", ok=True, fmt=Path(path).name)
