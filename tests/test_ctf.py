"""File identity, hash commands, and wordlist lookup for the CTF tabs."""

import tempfile
import unittest
from pathlib import Path

from core.crack import (
    build_commands,
    clean_hashes,
    detected_labels,
    identify_text,
)
from core.ctf_tools import file_tool, probe
from core.fileid import peel_base64, render_report
from core.wordlists import locate_wordlists


class FileIdTests(unittest.TestCase):
    def test_zip_header_is_named(self):
        report = render_report(b"PK\x03\x04" + b"\x00" * 16, name="blob.bin")
        self.assertIn("ZIP", report)
        self.assertIn("unzip", report)

    def test_base64_peel_reveals_the_zip(self):
        import base64

        raw = b"PK\x03\x04" + b"\x00" * 8
        text = base64.b64encode(raw).decode("ascii")
        self.assertEqual(peel_base64(text), raw)
        report = render_report(text.encode("ascii"), name="archive.xmi")
        self.assertIn("Peeled signature:", report)
        self.assertIn("ZIP", report)

    def test_ebcdic_space_and_cp037_preview(self):
        data = "RACF USER".encode("cp037")
        self.assertIn(b"\x40", data)
        report = render_report(data, name="users", needle="")
        self.assertIn("EBCDIC", report)
        self.assertIn("RACF USER", report)

    def test_evtx_and_registry_headers(self):
        self.assertIn("EVTX", render_report(b"ElfFile\x00" + b"\x00" * 8))
        self.assertIn("Registry", render_report(b"regf" + b"\x00" * 8))

    def test_xmi_ebcdic_header(self):
        report = render_report("INMR01".encode("cp037") + b"\x40" * 16)
        self.assertIn("XMIT", report)


class CrackTests(unittest.TestCase):
    def test_spaced_racf_lines_collapse(self):
        messy = "user one  $racf$*FIRE*$0123456789ABCDEF  trailing"
        self.assertEqual(clean_hashes(messy), "$racf$*FIRE*$0123456789ABCDEF")
        self.assertEqual(detected_labels(messy), ["RACF"])

    def test_thirty_two_hex_is_called_ambiguous(self):
        digest = "d41d8cd98f00b204e9800998ecf8427e"
        report = identify_text(digest)
        self.assertIn("MD5", report)
        self.assertIn("NTLM", report)

    def test_racf_best64_command(self):
        john, cat = build_commands(
            label="RACF",
            attack="best64",
            wordlist="/usr/share/wordlists/rockyou.txt",
            hash_name="hashes.txt",
            mask="",
            rule_path="/usr/share/hashcat/rules/best64.rule",
            john_installed=True,
            hashcat_installed=True,
        )
        self.assertIn("--format=racf", john.text)
        self.assertIn("--rules=best64", john.text)
        self.assertIn("-m 8500", cat.text)
        self.assertIn("best64.rule", cat.text)
        self.assertFalse(john.runnable)

    def test_missing_tool_still_copies(self):
        john, _cat = build_commands(
            label="MD5",
            attack="dictionary",
            wordlist="",
            hash_name="hashes.txt",
            mask="",
            rule_path=None,
            john_installed=False,
            hashcat_installed=False,
        )
        self.assertIn("john --format=raw-md5", john.text)
        self.assertFalse(john.runnable)
        self.assertIn("not installed", john.reason)

    def test_mask_does_not_need_a_wordlist(self):
        john, cat = build_commands(
            label="MD5",
            attack="mask",
            wordlist="",
            hash_name="hashes.txt",
            mask="SKY-HQNT-?d?d?d?d",
            rule_path=None,
            john_installed=True,
            hashcat_installed=True,
        )
        self.assertIn("--mask=SKY-HQNT-?d?d?d?d", john.text)
        self.assertIn("-a 3", cat.text)
        self.assertTrue(john.runnable)
        self.assertEqual(john.argv[0], "john")


class WordlistTests(unittest.TestCase):
    def test_scan_finds_a_local_list(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            ready = root / "lists"
            ready.mkdir()
            (ready / "rockyou.txt").write_text("secret\n", encoding="utf-8")
            hits = locate_wordlists(named=(), scan_dirs=[ready])
        self.assertTrue(any(hit.path.endswith("rockyou.txt") for hit in hits))
        self.assertTrue(all(hit.kind == "ready" for hit in hits))

    def test_missing_file_command_is_explicit(self):
        status = probe(["file-that-is-not-real"], "install note", which=lambda _name: None)
        self.assertFalse(status.installed)
        self.assertIn("not installed", status.detail)
        missing = file_tool(which=lambda _name: None)
        self.assertIn("not installed", missing.detail)


