#!/usr/bin/env python3
"""
Decoder — multi-tab encode / decode toolkit.
ASCII number lists, Base64, Hex, Binary, URL, HTML, ciphers, Morse, hashes.
"""

from __future__ import annotations

import re
import sys
import tkinter as tk
from pathlib import Path

# Allow running as script from any cwd
ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import customtkinter as ctk

from core.converters import Converters
from core.parsers import detect_list_format, parse_number_list

_UI_FAMILY = "Segoe UI" if sys.platform == "win32" else "DejaVu Sans"
_MONO_FAMILY = "Consolas" if sys.platform == "win32" else "DejaVu Sans Mono"


def font_ui(size: int = 12, weight: str = "normal") -> ctk.CTkFont:
    return ctk.CTkFont(family=_UI_FAMILY, size=size, weight=weight)


def font_mono(size: int = 13, weight: str = "normal") -> ctk.CTkFont:
    return ctk.CTkFont(family=_MONO_FAMILY, size=size, weight=weight)

# ── Theme: “enigma lab” — deep slate + cyan phosphor accent ──────────
COLORS = {
    "bg": "#0c1118",
    "panel": "#121a24",
    "panel2": "#182230",
    "border": "#243044",
    "text": "#e6edf5",
    "muted": "#8b9bb0",
    "accent": "#3dd6c6",
    "accent_dim": "#1f8f85",
    "accent2": "#7aa2ff",
    "danger": "#f07178",
    "ok": "#7fd99a",
    "input_bg": "#0a1018",
    "btn": "#1a2838",
    "btn_hover": "#243548",
}

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")


def copy_to_clipboard(widget: ctk.CTkBaseClass, text: str) -> None:
    try:
        widget.clipboard_clear()
        widget.clipboard_append(text)
        widget.update()
    except Exception:
        pass


class StatusBar(ctk.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color=COLORS["panel"], height=32, **kwargs)
        self.label = ctk.CTkLabel(
            self,
            text="Ready",
            text_color=COLORS["muted"],
            font=font_ui(12),
            anchor="w",
        )
        self.label.pack(side="left", fill="x", expand=True, padx=14, pady=4)
        self.format_label = ctk.CTkLabel(
            self,
            text="",
            text_color=COLORS["accent"],
            font=font_mono(size=11),
            anchor="e",
        )
        self.format_label.pack(side="right", padx=14, pady=4)

    def set(self, msg: str, *, ok: bool | None = None, fmt: str = "") -> None:
        color = COLORS["muted"]
        if ok is True:
            color = COLORS["ok"]
        elif ok is False:
            color = COLORS["danger"]
        self.label.configure(text=msg, text_color=color)
        if fmt is not None:
            self.format_label.configure(text=fmt)


class TextPane(ctk.CTkFrame):
    """Labeled multi-line text area with optional toolbar actions."""

    def __init__(
        self,
        master,
        title: str,
        *,
        height: int = 160,
        readonly: bool = False,
        **kwargs,
    ):
        super().__init__(master, fg_color="transparent", **kwargs)
        head = ctk.CTkFrame(self, fg_color="transparent")
        head.pack(fill="x", pady=(0, 4))
        ctk.CTkLabel(
            head,
            text=title,
            text_color=COLORS["muted"],
            font=font_ui(12, weight="bold"),
            anchor="w",
        ).pack(side="left")

        self._box = ctk.CTkTextbox(
            self,
            height=height,
            font=font_mono(size=13),
            fg_color=COLORS["input_bg"],
            text_color=COLORS["text"],
            border_color=COLORS["border"],
            border_width=1,
            corner_radius=8,
            wrap="word",
        )
        self._box.pack(fill="both", expand=True)
        if readonly:
            self._box.configure(state="disabled")
        self._readonly = readonly
        self._on_change = None

        tools = ctk.CTkFrame(self, fg_color="transparent")
        tools.pack(fill="x", pady=(4, 0))
        self._tools = tools

        ctk.CTkButton(
            tools,
            text="Copy",
            width=70,
            height=26,
            fg_color=COLORS["btn"],
            hover_color=COLORS["btn_hover"],
            text_color=COLORS["text"],
            font=ctk.CTkFont(size=11),
            command=self.copy,
        ).pack(side="right", padx=(4, 0))
        ctk.CTkButton(
            tools,
            text="Clear",
            width=70,
            height=26,
            fg_color=COLORS["btn"],
            hover_color=COLORS["btn_hover"],
            text_color=COLORS["text"],
            font=ctk.CTkFont(size=11),
            command=self.clear,
        ).pack(side="right", padx=(4, 0))
        if not readonly:
            ctk.CTkButton(
                tools,
                text="Paste",
                width=70,
                height=26,
                fg_color=COLORS["btn"],
                hover_color=COLORS["btn_hover"],
                text_color=COLORS["text"],
                font=ctk.CTkFont(size=11),
                command=self.paste,
            ).pack(side="right")

        self._box.bind("<Button-3>", self._on_context)
        if sys.platform == "darwin":
            self._box.bind("<Button-2>", self._on_context)

    def get(self) -> str:
        return self._box.get("1.0", "end-1c")

    def set(self, text: str) -> None:
        if self._readonly:
            self._box.configure(state="normal")
        self._box.delete("1.0", "end")
        self._box.insert("1.0", text)
        if self._readonly:
            self._box.configure(state="disabled")

    def clear(self) -> None:
        self.set("")

    def copy(self) -> None:
        copy_to_clipboard(self, self.get())

    def paste(self) -> None:
        if self._readonly:
            return
        try:
            clip = self.clipboard_get()
        except Exception:
            return
        if not clip:
            return
        try:
            self._box.delete("sel.first", "sel.last")
        except Exception:
            pass
        self._box.insert("insert", clip)
        if self._on_change:
            self._on_change()

    def select_all(self) -> None:
        try:
            self._box.tag_add("sel", "1.0", "end-1c")
            self._box.mark_set("insert", "end-1c")
        except Exception:
            pass

    def cut(self) -> None:
        if self._readonly:
            return
        try:
            sel = self._box.get("sel.first", "sel.last")
            copy_to_clipboard(self, sel)
            self._box.delete("sel.first", "sel.last")
        except Exception:
            pass

    def _on_context(self, event) -> None:
        menu = tk.Menu(self, tearoff=0)
        if not self._readonly:
            menu.add_command(label="Cut", command=self.cut)
        menu.add_command(label="Copy", command=self.copy)
        if not self._readonly:
            menu.add_command(label="Paste", command=self.paste)
        menu.add_separator()
        menu.add_command(label="Select all", command=self.select_all)
        menu.add_command(label="Clear", command=self.clear)
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def bind_change(self, callback) -> None:
        self._on_change = callback
        self._box.bind("<KeyRelease>", lambda e: callback())


class ActionRow(ctk.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)

    def add_btn(self, text: str, command, *, primary: bool = False) -> ctk.CTkButton:
        btn = ctk.CTkButton(
            self,
            text=text,
            height=34,
            corner_radius=8,
            font=font_ui(13, weight="bold"),
            fg_color=COLORS["accent"] if primary else COLORS["btn"],
            hover_color=COLORS["accent_dim"] if primary else COLORS["btn_hover"],
            text_color="#0a1018" if primary else COLORS["text"],
            command=command,
        )
        btn.pack(side="left", padx=(0, 8))
        return btn

    def add_option(self, label: str, values: list[str], default: str, width: int = 120):
        wrap = ctk.CTkFrame(self, fg_color="transparent")
        wrap.pack(side="left", padx=(0, 12))
        ctk.CTkLabel(
            wrap,
            text=label,
            text_color=COLORS["muted"],
            font=ctk.CTkFont(size=11),
        ).pack(side="left", padx=(0, 6))
        var = ctk.StringVar(value=default)
        menu = ctk.CTkOptionMenu(
            wrap,
            variable=var,
            values=values,
            width=width,
            height=30,
            fg_color=COLORS["btn"],
            button_color=COLORS["accent_dim"],
            button_hover_color=COLORS["accent"],
            dropdown_fg_color=COLORS["panel2"],
            font=ctk.CTkFont(size=12),
        )
        menu.pack(side="left")
        return var


# ══════════════════════════════════════════════════════════════════════
# Tabs
# ══════════════════════════════════════════════════════════════════════


class AsciiTab(ctk.CTkFrame):
    """ASCII / decimal / hex number lists ↔ text."""

    SAMPLE = (
        "values = [\n"
        "    72, 101, 108, 108, 111, 32, 68, 101, 99, 111, 100, 101, 114\n"
        "]"
    )

    def __init__(self, master, status: StatusBar, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.status = status

        info = ctk.CTkLabel(
            self,
            text=(
                "Paste number lists in almost any shape — brackets, commas, spaces, "
                "0x hex, \\x escapes, Python assignments, comments — then decode to text."
            ),
            text_color=COLORS["muted"],
            font=ctk.CTkFont(size=12),
            wraplength=900,
            justify="left",
            anchor="w",
        )
        info.pack(fill="x", pady=(0, 10))

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True)
        body.grid_columnconfigure(0, weight=1)
        body.grid_columnconfigure(1, weight=1)
        body.grid_rowconfigure(0, weight=1)

        left = ctk.CTkFrame(body, fg_color="transparent")
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        right = ctk.CTkFrame(body, fg_color="transparent")
        right.grid(row=0, column=1, sticky="nsew", padx=(8, 0))

        self.input_pane = TextPane(left, "Numbers / list input", height=280)
        self.input_pane.pack(fill="both", expand=True)
        self.input_pane.set(self.SAMPLE)

        self.output_pane = TextPane(right, "Text output", height=280)
        self.output_pane.pack(fill="both", expand=True)

        controls = ActionRow(self)
        controls.pack(fill="x", pady=(12, 0))

        self.base_var = controls.add_option(
            "Parse as",
            ["auto", "dec", "hex", "bin", "oct"],
            "auto",
            width=90,
        )
        self.out_style = controls.add_option(
            "Encode style",
            ["comma", "space", "brackets", "python", "hex_escape"],
            "brackets",
            width=110,
        )
        self.out_base = controls.add_option(
            "Encode base",
            ["dec", "hex", "bin", "oct"],
            "dec",
            width=80,
        )
        self.enc_var = controls.add_option(
            "Charset",
            ["latin-1", "utf-8", "ascii", "cp1252"],
            "latin-1",
            width=100,
        )

        controls.add_btn("Decode → Text", self.decode, primary=True)
        controls.add_btn("← Encode from Text", self.encode)
        controls.add_btn("Swap", self.swap)
        controls.add_btn("Load sample", self.load_sample)

        self.live = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(
            controls,
            text="Live decode",
            variable=self.live,
            text_color=COLORS["muted"],
            fg_color=COLORS["accent"],
            hover_color=COLORS["accent_dim"],
            font=ctk.CTkFont(size=12),
            command=self._on_live_toggle,
        ).pack(side="left", padx=(12, 0))

        self.input_pane.bind_change(self._maybe_live)
        self.decode()

    def load_sample(self) -> None:
        self.input_pane.set(self.SAMPLE)
        self.decode()

    def _on_live_toggle(self) -> None:
        if self.live.get():
            self.decode()

    def _maybe_live(self) -> None:
        if self.live.get():
            self.decode()

    def decode(self) -> None:
        raw = self.input_pane.get()
        fmt = detect_list_format(raw)
        nums, warn = parse_number_list(raw, base=self.base_var.get())  # type: ignore[arg-type]
        if not nums:
            self.output_pane.set("")
            self.status.set(warn or "No numbers found", ok=False, fmt=fmt)
            return
        try:
            text = Converters.numbers_to_text(nums, encoding=self.enc_var.get())
            self.output_pane.set(text)
            msg = f"Decoded {len(nums)} values → {len(text)} chars"
            if warn:
                msg += f"  ·  {warn}"
            self.status.set(msg, ok=True, fmt=fmt)
        except Exception as e:
            self.status.set(f"Decode error: {e}", ok=False, fmt=fmt)

    def encode(self) -> None:
        text = self.output_pane.get()
        if not text:
            text = self.input_pane.get()
            # if input looks like text not numbers, encode that
        try:
            # Prefer encoding whatever is in the text output if present,
            # else treat input as plain text when it doesn't parse as numbers.
            source = self.output_pane.get()
            if not source.strip():
                source = self.input_pane.get()
            nums = Converters.text_to_numbers(source, encoding=self.enc_var.get())
            formatted = Converters.format_numbers(
                nums,
                style=self.out_style.get(),
                base=self.out_base.get(),
            )
            self.input_pane.set(formatted)
            self.status.set(
                f"Encoded {len(source)} chars → {len(nums)} values",
                ok=True,
                fmt=self.out_style.get(),
            )
        except Exception as e:
            self.status.set(f"Encode error: {e}", ok=False)

    def swap(self) -> None:
        a, b = self.input_pane.get(), self.output_pane.get()
        self.input_pane.set(b)
        self.output_pane.set(a)
        self.status.set("Swapped panes", ok=True)


class BidirectionalTab(ctk.CTkFrame):
    """Generic left→right / right→left converter tab."""

    def __init__(
        self,
        master,
        status: StatusBar,
        *,
        title: str,
        left_label: str,
        right_label: str,
        to_right,
        to_left,
        sample_left: str = "",
        extra_controls=None,
        **kwargs,
    ):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.status = status
        self.to_right = to_right
        self.to_left = to_left
        self._extra = {}

        ctk.CTkLabel(
            self,
            text=title,
            text_color=COLORS["muted"],
            font=ctk.CTkFont(size=12),
            wraplength=900,
            justify="left",
            anchor="w",
        ).pack(fill="x", pady=(0, 10))

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True)
        body.grid_columnconfigure(0, weight=1)
        body.grid_columnconfigure(1, weight=1)
        body.grid_rowconfigure(0, weight=1)

        left = ctk.CTkFrame(body, fg_color="transparent")
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        right = ctk.CTkFrame(body, fg_color="transparent")
        right.grid(row=0, column=1, sticky="nsew", padx=(8, 0))

        self.left_pane = TextPane(left, left_label, height=280)
        self.left_pane.pack(fill="both", expand=True)
        self.right_pane = TextPane(right, right_label, height=280)
        self.right_pane.pack(fill="both", expand=True)

        if sample_left:
            self.left_pane.set(sample_left)

        controls = ActionRow(self)
        controls.pack(fill="x", pady=(12, 0))
        if extra_controls:
            self._extra = extra_controls(controls) or {}

        controls.add_btn("Encode →", self.encode, primary=True)
        controls.add_btn("← Decode", self.decode)
        controls.add_btn("Swap", self.swap)

        self.live = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(
            controls,
            text="Live",
            variable=self.live,
            text_color=COLORS["muted"],
            fg_color=COLORS["accent"],
            hover_color=COLORS["accent_dim"],
            font=ctk.CTkFont(size=12),
        ).pack(side="left", padx=(12, 0))

        self.left_pane.bind_change(self._maybe_live)
        if sample_left:
            self.encode()

    def _opts(self) -> dict:
        return {k: (v.get() if hasattr(v, "get") else v) for k, v in self._extra.items()}

    def _maybe_live(self) -> None:
        if self.live.get():
            self.encode()

    def encode(self) -> None:
        try:
            out = self.to_right(self.left_pane.get(), **self._opts())
            self.right_pane.set(out)
            self.status.set("Encoded", ok=True)
        except Exception as e:
            self.status.set(f"Error: {e}", ok=False)

    def decode(self) -> None:
        try:
            out = self.to_left(self.right_pane.get(), **self._opts())
            self.left_pane.set(out)
            self.status.set("Decoded", ok=True)
        except Exception as e:
            self.status.set(f"Error: {e}", ok=False)

    def swap(self) -> None:
        a, b = self.left_pane.get(), self.right_pane.get()
        self.left_pane.set(b)
        self.right_pane.set(a)


class CiphersTab(ctk.CTkFrame):
    def __init__(self, master, status: StatusBar, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.status = status

        ctk.CTkLabel(
            self,
            text="Classic transforms: ROT/Caesar, ROT47, Atbash, reverse, Morse, A1Z26.",
            text_color=COLORS["muted"],
            font=ctk.CTkFont(size=12),
            anchor="w",
        ).pack(fill="x", pady=(0, 10))

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True)
        body.grid_columnconfigure(0, weight=1)
        body.grid_columnconfigure(1, weight=1)
        body.grid_rowconfigure(0, weight=1)

        left = ctk.CTkFrame(body, fg_color="transparent")
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        right = ctk.CTkFrame(body, fg_color="transparent")
        right.grid(row=0, column=1, sticky="nsew", padx=(8, 0))

        self.in_pane = TextPane(left, "Input text", height=240)
        self.in_pane.pack(fill="both", expand=True)
        self.in_pane.set("uryyb jbeyq")
        self.out_pane = TextPane(right, "Output", height=240)
        self.out_pane.pack(fill="both", expand=True)

        controls = ActionRow(self)
        controls.pack(fill="x", pady=(10, 0))

        self.rot_var = controls.add_option(
            "ROT amount",
            [str(i) for i in range(1, 26)],
            "13",
            width=70,
        )

        controls.add_btn("ROT →", self.do_rot, primary=True)
        controls.add_btn("ROT back", self.do_rot_back)
        controls.add_btn("ROT47", self.do_rot47)
        controls.add_btn("Atbash", self.do_atbash)
        controls.add_btn("Reverse", self.do_rev)
        controls.add_btn("Rev words", self.do_rev_words)

        row2 = ActionRow(self)
        row2.pack(fill="x", pady=(8, 0))
        row2.add_btn("→ Morse", self.to_morse)
        row2.add_btn("← Morse", self.from_morse)
        row2.add_btn("→ A1Z26", self.to_a1z26)
        row2.add_btn("← A1Z26", self.from_a1z26)
        row2.add_btn("Swap", self.swap)

        self.do_rot()

    def do_rot(self) -> None:
        n = int(self.rot_var.get())
        self.out_pane.set(Converters.rot_n(self.in_pane.get(), n))
        self.status.set(f"ROT{n} applied", ok=True)

    def do_rot_back(self) -> None:
        n = int(self.rot_var.get())
        self.out_pane.set(Converters.rot_n(self.in_pane.get(), -n))
        self.status.set(f"ROT-{n} applied", ok=True)

    def do_rot47(self) -> None:
        self.out_pane.set(Converters.rot47(self.in_pane.get()))
        self.status.set("ROT47 applied (self-inverse)", ok=True)

    def do_atbash(self) -> None:
        self.out_pane.set(Converters.atbash(self.in_pane.get()))
        self.status.set("Atbash applied (self-inverse)", ok=True)

    def do_rev(self) -> None:
        self.out_pane.set(Converters.reverse_text(self.in_pane.get()))
        self.status.set("Reversed characters", ok=True)

    def do_rev_words(self) -> None:
        self.out_pane.set(Converters.reverse_words(self.in_pane.get()))
        self.status.set("Reversed words", ok=True)

    def to_morse(self) -> None:
        self.out_pane.set(Converters.to_morse(self.in_pane.get()))
        self.status.set("Encoded Morse", ok=True)

    def from_morse(self) -> None:
        src = self.in_pane.get()
        if not re_looks_morse(src):
            src = self.out_pane.get()
        self.out_pane.set(Converters.from_morse(src))
        self.status.set("Decoded Morse", ok=True)

    def to_a1z26(self) -> None:
        self.out_pane.set(Converters.a1z26_encode(self.in_pane.get()))
        self.status.set("A1Z26 encoded", ok=True)

    def from_a1z26(self) -> None:
        src = self.out_pane.get() if re.search(r"\d", self.out_pane.get()) else self.in_pane.get()
        self.out_pane.set(Converters.a1z26_decode(src))
        self.status.set("A1Z26 decoded", ok=True)

    def swap(self) -> None:
        a, b = self.in_pane.get(), self.out_pane.get()
        self.in_pane.set(b)
        self.out_pane.set(a)


def re_looks_morse(s: str) -> bool:
    return bool(s) and all(c in ".-/ \t\n" for c in s)


class CryptoTab(ctk.CTkFrame):
    """Key-based encrypt / decrypt: Vigenère, XOR, Rail Fence."""

    def __init__(self, master, status: StatusBar, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.status = status

        ctk.CTkLabel(
            self,
            text=(
                "Key-based crypto: Vigenère, XOR (text/hex key), Rail Fence. "
                "Not a substitute for modern ciphers — great for CTF & learning."
            ),
            text_color=COLORS["muted"],
            font=ctk.CTkFont(size=12),
            wraplength=900,
            justify="left",
            anchor="w",
        ).pack(fill="x", pady=(0, 10))

        # Key / options bar
        opts = ctk.CTkFrame(self, fg_color=COLORS["panel"], corner_radius=10)
        opts.pack(fill="x", pady=(0, 10))
        oinner = ctk.CTkFrame(opts, fg_color="transparent")
        oinner.pack(fill="x", padx=12, pady=10)

        ctk.CTkLabel(
            oinner,
            text="Key",
            text_color=COLORS["muted"],
            font=ctk.CTkFont(size=12, weight="bold"),
        ).pack(side="left", padx=(0, 8))
        self.key_entry = ctk.CTkEntry(
            oinner,
            width=220,
            height=32,
            fg_color=COLORS["input_bg"],
            border_color=COLORS["border"],
            text_color=COLORS["text"],
            placeholder_text="secret / 0xDEAD…",
            font=font_mono(size=13),
        )
        self.key_entry.pack(side="left", padx=(0, 16))
        self.key_entry.insert(0, "KEY")

        self.cipher_var = ctk.StringVar(value="Vigenère")
        ctk.CTkLabel(
            oinner, text="Cipher", text_color=COLORS["muted"], font=ctk.CTkFont(size=11)
        ).pack(side="left", padx=(0, 6))
        ctk.CTkOptionMenu(
            oinner,
            variable=self.cipher_var,
            values=["Vigenère", "XOR", "Rail Fence"],
            width=120,
            height=30,
            fg_color=COLORS["btn"],
            button_color=COLORS["accent_dim"],
            button_hover_color=COLORS["accent"],
            dropdown_fg_color=COLORS["panel2"],
            command=lambda _=None: self._sync_options(),
        ).pack(side="left", padx=(0, 12))

        self.xor_key_hex = ctk.BooleanVar(value=False)
        self.xor_hex_cb = ctk.CTkCheckBox(
            oinner,
            text="Key is hex",
            variable=self.xor_key_hex,
            text_color=COLORS["muted"],
            fg_color=COLORS["accent"],
            hover_color=COLORS["accent_dim"],
            font=ctk.CTkFont(size=12),
        )
        self.xor_hex_cb.pack(side="left", padx=(0, 12))

        self.xor_out = ctk.StringVar(value="hex")
        ctk.CTkLabel(
            oinner, text="XOR out", text_color=COLORS["muted"], font=ctk.CTkFont(size=11)
        ).pack(side="left", padx=(0, 6))
        self.xor_out_menu = ctk.CTkOptionMenu(
            oinner,
            variable=self.xor_out,
            values=["hex", "base64", "text"],
            width=90,
            height=30,
            fg_color=COLORS["btn"],
            button_color=COLORS["accent_dim"],
            button_hover_color=COLORS["accent"],
            dropdown_fg_color=COLORS["panel2"],
        )
        self.xor_out_menu.pack(side="left", padx=(0, 12))

        self.rails_var = ctk.StringVar(value="3")
        ctk.CTkLabel(
            oinner, text="Rails", text_color=COLORS["muted"], font=ctk.CTkFont(size=11)
        ).pack(side="left", padx=(0, 6))
        self.rails_menu = ctk.CTkOptionMenu(
            oinner,
            variable=self.rails_var,
            values=[str(i) for i in range(2, 11)],
            width=70,
            height=30,
            fg_color=COLORS["btn"],
            button_color=COLORS["accent_dim"],
            button_hover_color=COLORS["accent"],
            dropdown_fg_color=COLORS["panel2"],
        )
        self.rails_menu.pack(side="left")

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True)
        body.grid_columnconfigure(0, weight=1)
        body.grid_columnconfigure(1, weight=1)
        body.grid_rowconfigure(0, weight=1)

        left = ctk.CTkFrame(body, fg_color="transparent")
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        right = ctk.CTkFrame(body, fg_color="transparent")
        right.grid(row=0, column=1, sticky="nsew", padx=(8, 0))

        self.in_pane = TextPane(left, "Plaintext", height=240)
        self.in_pane.pack(fill="both", expand=True)
        self.in_pane.set("ATTACKATDAWN")
        self.out_pane = TextPane(right, "Ciphertext", height=240)
        self.out_pane.pack(fill="both", expand=True)

        row = ActionRow(self)
        row.pack(fill="x", pady=(12, 0))
        row.add_btn("Encrypt →", self.encrypt, primary=True)
        row.add_btn("← Decrypt", self.decrypt)
        row.add_btn("Swap", self.swap)

        self._sync_options()

    def _sync_options(self) -> None:
        mode = self.cipher_var.get()
        is_xor = mode == "XOR"
        is_rail = mode == "Rail Fence"
        # CTk widgets don't hide easily — just leave visible; disabled feel via state
        state_xor = "normal" if is_xor else "disabled"
        state_rail = "normal" if is_rail else "disabled"
        try:
            self.xor_hex_cb.configure(state=state_xor)
            self.xor_out_menu.configure(state=state_xor)
            self.rails_menu.configure(state=state_rail)
            self.key_entry.configure(state="disabled" if is_rail else "normal")
        except Exception:
            pass

    def encrypt(self) -> None:
        try:
            mode = self.cipher_var.get()
            text = self.in_pane.get()
            key = self.key_entry.get()
            if mode == "Vigenère":
                out = Converters.vigenere(text, key, decrypt=False)
            elif mode == "XOR":
                out = Converters.xor_crypt(
                    text,
                    key,
                    key_is_hex=self.xor_key_hex.get(),
                    output=self.xor_out.get(),
                )
            else:
                out = Converters.rail_fence_encrypt(text, int(self.rails_var.get()))
            self.out_pane.set(out)
            self.status.set(f"{mode} encrypted", ok=True)
        except Exception as e:
            self.status.set(f"Encrypt error: {e}", ok=False)

    def decrypt(self) -> None:
        try:
            mode = self.cipher_var.get()
            cipher = self.out_pane.get() or self.in_pane.get()
            key = self.key_entry.get()
            if mode == "Vigenère":
                plain = Converters.vigenere(cipher, key, decrypt=True)
            elif mode == "XOR":
                # if output was hex/b64, treat ciphertext format accordingly
                fmt = self.xor_out.get()
                if fmt == "text":
                    plain = Converters.xor_crypt(
                        cipher, key, key_is_hex=self.xor_key_hex.get(), output="text"
                    )
                else:
                    plain = Converters.xor_decrypt_from(
                        cipher,
                        key,
                        key_is_hex=self.xor_key_hex.get(),
                        input_fmt=fmt,
                    )
            else:
                plain = Converters.rail_fence_decrypt(cipher, int(self.rails_var.get()))
            self.in_pane.set(plain)
            self.status.set(f"{mode} decrypted", ok=True)
        except Exception as e:
            self.status.set(f"Decrypt error: {e}", ok=False)

    def swap(self) -> None:
        a, b = self.in_pane.get(), self.out_pane.get()
        self.in_pane.set(b)
        self.out_pane.set(a)


class UnicodeTab(ctk.CTkFrame):
    def __init__(self, master, status: StatusBar, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.status = status

        ctk.CTkLabel(
            self,
            text="Unicode code points, escapes, and a quick byte summary of your text.",
            text_color=COLORS["muted"],
            font=ctk.CTkFont(size=12),
            anchor="w",
        ).pack(fill="x", pady=(0, 10))

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True)
        body.grid_columnconfigure(0, weight=1)
        body.grid_columnconfigure(1, weight=1)
        body.grid_rowconfigure(0, weight=1)

        left = ctk.CTkFrame(body, fg_color="transparent")
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        right = ctk.CTkFrame(body, fg_color="transparent")
        right.grid(row=0, column=1, sticky="nsew", padx=(8, 0))

        self.in_pane = TextPane(left, "Text", height=200)
        self.in_pane.pack(fill="both", expand=True)
        self.in_pane.set("Hello Decoder")
        self.out_pane = TextPane(right, "Code points / summary", height=200)
        self.out_pane.pack(fill="both", expand=True)

        controls = ActionRow(self)
        controls.pack(fill="x", pady=(12, 0))
        self.style_var = controls.add_option(
            "Style",
            ["U+", "\\u", "decimal"],
            "U+",
            width=100,
        )
        controls.add_btn("Text → Code points", self.to_cp, primary=True)
        controls.add_btn("Code points → Text", self.from_cp)
        controls.add_btn("Byte summary", self.summary)

        self.to_cp()

    def to_cp(self) -> None:
        self.out_pane.set(
            Converters.text_to_codepoints(self.in_pane.get(), style=self.style_var.get())
        )
        self.status.set("Code points generated", ok=True)

    def from_cp(self) -> None:
        src = self.out_pane.get() or self.in_pane.get()
        self.in_pane.set(Converters.codepoints_to_text(src))
        self.status.set("Code points decoded", ok=True)

    def summary(self) -> None:
        self.out_pane.set(Converters.byte_summary(self.in_pane.get()))
        self.status.set("Byte summary ready", ok=True)


class HashCheckTab(ctk.CTkFrame):
    """Generate digests and verify text or downloaded files against an expected hash."""

    def __init__(self, master, status: StatusBar, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.status = status
        self._file_path: str | None = None

        ctk.CTkLabel(
            self,
            text=(
                "Paste a hash on the left and a candidate string on the right, then Verify. "
                "Works the other way around too (plain text → digest). "
                "File mode stream-hashes downloads so large installers do not need to fit in RAM. "
                "Use Paste or right-click if Ctrl+V is flaky."
            ),
            text_color=COLORS["muted"],
            font=ctk.CTkFont(size=12),
            wraplength=900,
            justify="left",
            anchor="w",
        ).pack(fill="x", pady=(0, 8))

        # Source mode: Text vs File
        mode_row = ctk.CTkFrame(self, fg_color=COLORS["panel"], corner_radius=10)
        mode_row.pack(fill="x", pady=(0, 8))
        minner = ctk.CTkFrame(mode_row, fg_color="transparent")
        minner.pack(fill="x", padx=12, pady=8)

        ctk.CTkLabel(
            minner,
            text="Source",
            text_color=COLORS["muted"],
            font=ctk.CTkFont(size=12, weight="bold"),
        ).pack(side="left", padx=(0, 10))

        self.source_var = ctk.StringVar(value="Text")
        self.source_seg = ctk.CTkSegmentedButton(
            minner,
            values=["Text", "File"],
            variable=self.source_var,
            command=self._on_source_change,
            fg_color=COLORS["btn"],
            selected_color=COLORS["accent_dim"],
            selected_hover_color=COLORS["accent"],
            unselected_color=COLORS["btn"],
            unselected_hover_color=COLORS["btn_hover"],
            text_color=COLORS["text"],
            font=ctk.CTkFont(size=12),
        )
        self.source_seg.pack(side="left", padx=(0, 16))

        self.browse_btn = ctk.CTkButton(
            minner,
            text="Browse file…",
            width=120,
            height=30,
            fg_color=COLORS["btn"],
            hover_color=COLORS["btn_hover"],
            text_color=COLORS["text"],
            font=ctk.CTkFont(size=12),
            command=self.browse_file,
        )
        self.browse_btn.pack(side="left", padx=(0, 10))

        self.clear_file_btn = ctk.CTkButton(
            minner,
            text="Clear file",
            width=90,
            height=30,
            fg_color=COLORS["btn"],
            hover_color=COLORS["btn_hover"],
            text_color=COLORS["text"],
            font=ctk.CTkFont(size=12),
            command=self.clear_file,
        )
        self.clear_file_btn.pack(side="left", padx=(0, 12))

        self.file_label = ctk.CTkLabel(
            minner,
            text="No file selected",
            text_color=COLORS["muted"],
            font=font_mono(size=11),
            anchor="w",
        )
        self.file_label.pack(side="left", fill="x", expand=True)

        # Verdict banner
        self.verdict = ctk.CTkLabel(
            self,
            text="Paste a hash and a candidate, then Verify",
            text_color=COLORS["muted"],
            font=font_ui(size=15, weight="bold"),
            fg_color=COLORS["panel"],
            corner_radius=8,
            height=44,
        )
        self.verdict.pack(fill="x", pady=(0, 8))

        top = ctk.CTkFrame(self, fg_color="transparent")
        top.pack(fill="x")
        top.grid_columnconfigure(0, weight=1)
        top.grid_columnconfigure(1, weight=1)

        left = ctk.CTkFrame(top, fg_color="transparent")
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        right = ctk.CTkFrame(top, fg_color="transparent")
        right.grid(row=0, column=1, sticky="nsew", padx=(8, 0))

        self.expected_pane = TextPane(left, "Hash to check — paste here", height=120)
        self.expected_pane.pack(fill="both", expand=True)
        # md5 of "hello"
        self.expected_pane.set("5d41402abc4b2a76b9719d911017c592")

        self.text_pane = TextPane(right, "Candidate plaintext", height=120)
        self.text_pane.pack(fill="both", expand=True)
        self.text_pane.set("hello")

        row = ActionRow(self)
        row.pack(fill="x", pady=(10, 0))
        self.algo = row.add_option(
            "Algorithm",
            ["auto"] + list(Converters.HASH_ALGOS),
            "auto",
            width=120,
        )
        row.add_btn("Verify hash", self.verify, primary=True)
        row.add_btn("Hash candidate", self.hash_once)
        row.add_btn("Hash all algos", self.hash_all)
        row.add_btn("Swap fields", self.swap_fields)

        self.live = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(
            row,
            text="Live verify",
            variable=self.live,
            text_color=COLORS["muted"],
            fg_color=COLORS["accent"],
            hover_color=COLORS["accent_dim"],
            font=ctk.CTkFont(size=12),
            command=lambda: self.verify() if self.live.get() else None,
        ).pack(side="left", padx=(12, 0))

        self.result_pane = TextPane(self, "Result / digests", height=180)
        self.result_pane.pack(fill="both", expand=True, pady=(10, 0))

        self.expected_pane.bind_change(self._maybe_live)
        self.text_pane.bind_change(self._maybe_live)

        self._on_source_change("Text")
        self.verify()

    def _on_source_change(self, value: str | None = None) -> None:
        mode = value or self.source_var.get()
        is_file = mode == "File"
        state = "normal" if is_file else "disabled"
        try:
            self.browse_btn.configure(state=state)
            self.clear_file_btn.configure(state=state)
        except Exception:
            pass
        if is_file and self._file_path:
            self._set_verdict(None, f"File mode · {self._file_path}")
        elif is_file:
            self._set_verdict(None, "File mode · browse to a downloaded file")
        else:
            self._set_verdict(None, "Text mode · paste hash (left) and candidate (right)")

    def browse_file(self) -> None:
        from tkinter import filedialog

        path = filedialog.askopenfilename(
            title="Select file to hash / verify",
            filetypes=[
                ("All files", "*.*"),
                ("Installers", "*.exe;*.msi;*.dmg;*.pkg;*.AppImage"),
                ("Archives", "*.zip;*.7z;*.rar;*.tar;*.gz;*.bz2;*.xz"),
                ("ISO / images", "*.iso;*.img"),
            ],
        )
        if not path:
            return
        self._file_path = path
        self.source_var.set("File")
        try:
            size = Converters.file_size_label(path)
        except OSError:
            size = "?"
        name = Path(path).name
        self.file_label.configure(
            text=f"{name}  ·  {size}  ·  {path}",
            text_color=COLORS["accent"],
        )
        self._on_source_change("File")
        self.status.set(f"Selected file ({size})", ok=True, fmt=name)

    def clear_file(self) -> None:
        self._file_path = None
        self.file_label.configure(text="No file selected", text_color=COLORS["muted"])
        self.status.set("File cleared", ok=True)

    def _using_file(self) -> bool:
        return self.source_var.get() == "File"

    def _set_verdict(self, matched: bool | None, detail: str) -> None:
        if matched is True:
            self.verdict.configure(
                text=f"  ✓  MATCH  —  {detail}",
                text_color=COLORS["ok"],
                fg_color="#0f2a1c",
            )
        elif matched is False:
            self.verdict.configure(
                text=f"  ✗  NO MATCH  —  {detail}",
                text_color=COLORS["danger"],
                fg_color="#2a1214",
            )
        else:
            self.verdict.configure(
                text=f"  ·  {detail}",
                text_color=COLORS["muted"],
                fg_color=COLORS["panel"],
            )

    def _maybe_live(self) -> None:
        if not self.live.get() or self._using_file():
            return
        if self.expected_pane.get().strip() and self.text_pane.get().strip():
            self.verify()

    def swap_fields(self) -> None:
        a, b = self.expected_pane.get(), self.text_pane.get()
        self.expected_pane.set(b)
        self.text_pane.set(a)
        if self.live.get():
            self.verify()

    def _pair_for_text_verify(self) -> tuple[str, str]:
        """Return (candidate_text, expected_hash), swapping if the user pasted the hash on the right."""
        left = self.expected_pane.get()
        right = self.text_pane.get()
        left_is_hash = Converters.looks_like_hash(left)
        right_is_hash = Converters.looks_like_hash(right)
        if right_is_hash and not left_is_hash:
            return left, right
        return right, left

    def verify(self) -> None:
        try:
            if self._using_file():
                expected = self.expected_pane.get().strip()
                if not Converters.looks_like_hash(expected) and Converters.looks_like_hash(
                    self.text_pane.get()
                ):
                    expected = self.text_pane.get()
                if not expected.strip():
                    self._set_verdict(None, "Paste a hex hash to verify the file against")
                    self.status.set("No expected hash", ok=False)
                    return
                if not self._file_path:
                    self._set_verdict(None, "Browse to a file first")
                    self.status.set("No file selected", ok=False)
                    return
                self._set_verdict(None, "Hashing file… (large downloads may take a moment)")
                self.update_idletasks()
                result = Converters.verify_file_hash(
                    self._file_path, expected, self.algo.get()
                )
                src_line = f"File     : {self._file_path}"
                size_line = f"Size     : {result.get('size', '?')}"
            else:
                candidate, expected = self._pair_for_text_verify()
                if not expected.strip():
                    self._set_verdict(None, "Paste a hex hash in either box")
                    self.status.set("No hash to check", ok=False)
                    return
                if not candidate.strip():
                    self._set_verdict(None, "Paste the candidate plaintext in the other box")
                    self.status.set("No candidate text", ok=False)
                    return
                result = Converters.verify_hash(
                    candidate, expected, self.algo.get()
                )
                src_line = "Source   : candidate text"
                size_line = f"Chars    : {len(candidate)}"

            if result["match"]:
                self._set_verdict(
                    True,
                    f"{result['algo'].upper()}  ·  {result['computed']}",
                )
                lines = [
                    "Status   : MATCH",
                    src_line,
                    size_line,
                    f"Algorithm: {result['algo']}",
                    f"Computed : {result['computed']}",
                    f"Expected : {result['expected']}",
                    f"Tried    : {', '.join(result['tried'])}",
                ]
                self.result_pane.set("\n".join(lines))
                self.status.set(
                    f"Hash MATCH ({result['algo']})",
                    ok=True,
                    fmt=result["algo"],
                )
            else:
                hints = Converters.guess_hash_algos(expected)
                hint_s = ", ".join(hints) if hints else "unknown length"
                self._set_verdict(
                    False,
                    f"tried {len(result['tried'])} algos  ·  length hints: {hint_s}",
                )
                lines = [
                    "Status   : NO MATCH",
                    src_line,
                    size_line,
                    f"Expected : {result['expected']}  ({len(result['expected'])} hex chars)",
                    f"Length → : {hint_s}",
                    f"Sample   : {result['algo']} = {result['computed']}",
                    f"Tried    : {', '.join(result['tried'])}",
                    "",
                    "Tip: confirm the publisher used the same algorithm (often SHA-256).",
                ]
                self.result_pane.set("\n".join(lines))
                self.status.set("Hash NO MATCH", ok=False, fmt=hint_s)
        except Exception as e:
            self._set_verdict(None, str(e))
            self.status.set(f"Verify error: {e}", ok=False)

    def hash_once(self) -> None:
        try:
            algo = self.algo.get()
            if algo == "auto":
                algo = "sha256"
            if self._using_file():
                if not self._file_path:
                    self.status.set("No file selected", ok=False)
                    return
                self._set_verdict(None, f"Hashing file with {algo}…")
                self.update_idletasks()
                dig = Converters.hash_file(self._file_path, algo)
                size = Converters.file_size_label(self._file_path)
                self.result_pane.set(
                    f"File  : {self._file_path}\nSize  : {size}\n{algo:12}  {dig}"
                )
            else:
                dig = Converters.hash_text(self.text_pane.get(), algo)
                self.result_pane.set(f"{algo:12}  {dig}")
            self.expected_pane.set(dig)
            self._set_verdict(None, f"Generated {algo.upper()} (copied into Expected)")
            self.status.set(f"{algo.upper()} digest ready", ok=True, fmt=algo)
        except Exception as e:
            self.status.set(f"Hash error: {e}", ok=False)

    def hash_all(self) -> None:
        try:
            if self._using_file():
                if not self._file_path:
                    self.status.set("No file selected", ok=False)
                    return
                self._set_verdict(None, "Hashing file with all algorithms (one pass)…")
                self.update_idletasks()
                digests = Converters.hash_file_multi(self._file_path)
                header = [
                    f"File  : {self._file_path}",
                    f"Size  : {Converters.file_size_label(self._file_path)}",
                    "",
                ]
            else:
                digests = Converters.hash_all(self.text_pane.get())
                header = []

            lines = header + [f"{a:12}  {h}" for a, h in digests.items()]
            expected = Converters.normalize_hash(self.expected_pane.get())
            if expected:
                lines.append("")
                for a, h in digests.items():
                    if h.lower() == expected:
                        lines.append(f">>> MATCH on {a}")
                        self._set_verdict(True, f"{a.upper()}  ·  {h}")
                        break
                else:
                    self._set_verdict(False, "no algorithm matched expected hash")
            else:
                self._set_verdict(None, f"Computed {len(digests)} digests")
            self.result_pane.set("\n".join(lines))
            self.status.set(f"Hashed with {len(digests)} algorithms", ok=True)
        except Exception as e:
            self.status.set(f"Hash error: {e}", ok=False)


class MultiTab(ctk.CTkFrame):
    """Run several common decoders at once for quick CTF triage."""

    def __init__(self, master, status: StatusBar, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.status = status

        ctk.CTkLabel(
            self,
            text=(
                "Paste unknown data once — try Base64, Hex, Binary, URL, ASCII list, "
                "and ROT13 in parallel."
            ),
            text_color=COLORS["muted"],
            font=ctk.CTkFont(size=12),
            anchor="w",
        ).pack(fill="x", pady=(0, 10))

        self.in_pane = TextPane(self, "Unknown input", height=120)
        self.in_pane.pack(fill="x")
        self.in_pane.set("SGVsbG8gRGVjb2Rlcg==")

        row = ActionRow(self)
        row.pack(fill="x", pady=10)
        row.add_btn("Try all decoders", self.try_all, primary=True)

        self.out_pane = TextPane(self, "Results", height=320)
        self.out_pane.pack(fill="both", expand=True)
        self.try_all()

    def try_all(self) -> None:
        raw = self.in_pane.get().strip()
        if not raw:
            self.status.set("Nothing to decode", ok=False)
            return

        blocks: list[str] = []

        def attempt(name: str, fn) -> None:
            try:
                result = fn()
                if result is None or result == "":
                    return
                preview = result if len(result) < 400 else result[:400] + "…"
                # skip if result is mostly garbage control chars
                printable = sum(1 for c in result if c.isprintable() or c in "\n\r\t")
                ratio = printable / max(len(result), 1)
                flag = "✓" if ratio > 0.85 else "~"
                blocks.append(f"{flag} {name}\n{preview}\n")
            except Exception as e:
                blocks.append(f"✗ {name}\n  ({e})\n")

        attempt("Base64", lambda: Converters.b64_decode(raw))
        attempt("Base64 URL-safe", lambda: Converters.b64_decode(raw, urlsafe=True))
        attempt("Base32", lambda: Converters.b32_decode(raw))
        attempt("Base85", lambda: Converters.b85_decode(raw))
        attempt("Ascii85", lambda: Converters.a85_decode(raw))
        attempt("Hex → text", lambda: Converters.hex_to_text(raw))
        attempt("Binary → text", lambda: Converters.binary_to_text(raw))
        attempt("URL decode", lambda: Converters.url_decode(raw))
        attempt("HTML unescape", lambda: Converters.html_decode(raw))
        attempt("ROT13", lambda: Converters.rot_n(raw, 13))
        attempt("ROT47", lambda: Converters.rot47(raw))
        attempt("Atbash", lambda: Converters.atbash(raw))
        attempt("Reverse", lambda: Converters.reverse_text(raw))
        attempt("A1Z26", lambda: Converters.a1z26_decode(raw))

        nums, err = parse_number_list(raw)
        if nums:
            attempt(
                f"ASCII list ({len(nums)} values)",
                lambda: Converters.numbers_to_text(nums),
            )
        elif err:
            blocks.append(f"· ASCII list\n  ({err})\n")

        if re_looks_morse(raw):
            attempt("Morse", lambda: Converters.from_morse(raw))

        self.out_pane.set("\n".join(blocks) if blocks else "No decoders produced output.")
        self.status.set(f"Tried common decoders on {len(raw)} chars", ok=True)


# ══════════════════════════════════════════════════════════════════════
# App shell
# ══════════════════════════════════════════════════════════════════════


class DecoderApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Decoder — Enigma Lab")
        self.geometry("1100x720")
        self.minsize(900, 600)
        self.configure(fg_color=COLORS["bg"])

        try:
            self.iconbitmap(default="")  # no icon file required
        except Exception:
            pass

        # Header
        header = ctk.CTkFrame(self, fg_color=COLORS["panel"], height=64, corner_radius=0)
        header.pack(fill="x")
        header.pack_propagate(False)

        title_wrap = ctk.CTkFrame(header, fg_color="transparent")
        title_wrap.pack(side="left", padx=20, pady=10)

        ctk.CTkLabel(
            title_wrap,
            text="DECODER",
            text_color=COLORS["accent"],
            font=font_ui(size=22, weight="bold"),
            anchor="w",
        ).pack(anchor="w")
        ctk.CTkLabel(
            title_wrap,
            text="ASCII · Base · Hex · Crypto · Ciphers · Hash Check · Try All",
            text_color=COLORS["muted"],
            font=font_ui(size=11),
            anchor="w",
        ).pack(anchor="w")

        ctk.CTkLabel(
            header,
            text="enigma lab",
            text_color=COLORS["accent2"],
            font=font_mono(size=12),
        ).pack(side="right", padx=20)

        # Status
        self.status = StatusBar(self)
        self.status.pack(fill="x", side="bottom")

        # Tabs
        self.tabs = ctk.CTkTabview(
            self,
            fg_color=COLORS["bg"],
            segmented_button_fg_color=COLORS["panel"],
            segmented_button_selected_color=COLORS["accent_dim"],
            segmented_button_selected_hover_color=COLORS["accent"],
            segmented_button_unselected_color=COLORS["panel"],
            segmented_button_unselected_hover_color=COLORS["btn_hover"],
            text_color=COLORS["text"],
            corner_radius=10,
        )
        self.tabs.pack(fill="both", expand=True, padx=16, pady=(12, 8))

        tab_ascii = self.tabs.add("ASCII Lists")
        tab_b64 = self.tabs.add("Base / Encodings")
        tab_hex = self.tabs.add("Hex / Binary")
        tab_web = self.tabs.add("URL / HTML")
        tab_cipher = self.tabs.add("Ciphers")
        tab_crypto = self.tabs.add("Crypto")
        tab_hash = self.tabs.add("Hash Check")
        tab_uni = self.tabs.add("Unicode")
        tab_multi = self.tabs.add("Try All")

        all_tabs = (
            tab_ascii,
            tab_b64,
            tab_hex,
            tab_web,
            tab_cipher,
            tab_crypto,
            tab_hash,
            tab_uni,
            tab_multi,
        )
        for t in all_tabs:
            t.configure(fg_color=COLORS["bg"])

        AsciiTab(tab_ascii, self.status).pack(fill="both", expand=True, padx=4, pady=4)

        def base_encode(t, mode="Base64", **k):
            if mode == "Base64":
                return Converters.b64_encode(t)
            if mode == "Base64 URL-safe":
                return Converters.b64_encode(t, urlsafe=True)
            if mode == "Base32":
                return Converters.b32_encode(t)
            if mode == "Base85":
                return Converters.b85_encode(t)
            if mode == "Ascii85":
                return Converters.a85_encode(t)
            return Converters.b64_encode(t)

        def base_decode(t, mode="Base64", **k):
            if mode == "Base64":
                return Converters.b64_decode(t)
            if mode == "Base64 URL-safe":
                return Converters.b64_decode(t, urlsafe=True)
            if mode == "Base32":
                return Converters.b32_decode(t)
            if mode == "Base85":
                return Converters.b85_decode(t)
            if mode == "Ascii85":
                return Converters.a85_decode(t)
            return Converters.b64_decode(t)

        BidirectionalTab(
            tab_b64,
            self.status,
            title="Base64, Base64 URL-safe, Base32, Base85, and Ascii85.",
            left_label="Plain text",
            right_label="Encoded",
            to_right=base_encode,
            to_left=base_decode,
            sample_left="Hello Decoder",
            extra_controls=lambda row: {
                "mode": row.add_option(
                    "Mode",
                    ["Base64", "Base64 URL-safe", "Base32", "Base85", "Ascii85"],
                    "Base64",
                    width=140,
                )
            },
        ).pack(fill="both", expand=True, padx=4, pady=4)

        BidirectionalTab(
            tab_hex,
            self.status,
            title="Hex and binary byte representations of text.",
            left_label="Plain text",
            right_label="Hex / Binary output",
            to_right=lambda t, mode="hex", **k: (
                Converters.text_to_hex(t)
                if mode == "hex"
                else Converters.text_to_binary(t)
                if mode == "binary"
                else Converters.text_to_hex(t, sep="")
            ),
            to_left=lambda t, mode="hex", **k: (
                Converters.hex_to_text(t)
                if mode in ("hex", "hex compact")
                else Converters.binary_to_text(t)
            ),
            sample_left="Hello Decoder",
            extra_controls=lambda row: {
                "mode": row.add_option(
                    "Format",
                    ["hex", "hex compact", "binary"],
                    "hex",
                    width=120,
                )
            },
        ).pack(fill="both", expand=True, padx=4, pady=4)

        BidirectionalTab(
            tab_web,
            self.status,
            title="URL percent-encoding and HTML entity encode / decode.",
            left_label="Plain text",
            right_label="Encoded",
            to_right=lambda t, kind="URL (quote+)", **k: (
                Converters.url_encode(t, quote_plus=True)
                if kind.startswith("URL")
                else Converters.html_encode(t)
            ),
            to_left=lambda t, kind="URL (quote+)", **k: (
                Converters.url_decode(t)
                if kind.startswith("URL")
                else Converters.html_decode(t)
            ),
            sample_left="hello world & CTF? x=1",
            extra_controls=lambda row: {
                "kind": row.add_option(
                    "Type",
                    ["URL (quote+)", "HTML entities"],
                    "URL (quote+)",
                    width=130,
                )
            },
        ).pack(fill="both", expand=True, padx=4, pady=4)

        CiphersTab(tab_cipher, self.status).pack(fill="both", expand=True, padx=4, pady=4)
        CryptoTab(tab_crypto, self.status).pack(fill="both", expand=True, padx=4, pady=4)
        HashCheckTab(tab_hash, self.status).pack(fill="both", expand=True, padx=4, pady=4)
        UnicodeTab(tab_uni, self.status).pack(fill="both", expand=True, padx=4, pady=4)
        MultiTab(tab_multi, self.status).pack(fill="both", expand=True, padx=4, pady=4)

        self.protocol("WM_DELETE_WINDOW", self.destroy)
        self.status.set("Ready — Enigma Lab loaded", ok=True, fmt="brackets")


def main() -> None:
    app = DecoderApp()
    app.mainloop()


if __name__ == "__main__":
    main()
