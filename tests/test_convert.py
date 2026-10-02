"""Checks for cipher round-trips and hex/binary that used to grow an extra byte."""

import unittest

from core.chart import lookup
from core.converters import Converters, parse_binary_bytes, parse_hex_bytes
from core.parsers import parse_number_list


class HexBinaryTests(unittest.TestCase):
    def test_0x_prefixes_do_not_add_a_byte(self):
        self.assertEqual(parse_hex_bytes("0x48 0x65 0x6c 0x6c 0x6f"), b"Hello")
        self.assertEqual(Converters.hex_to_text("0x48,0x65,0x6c,0x6c,0x6f"), "Hello")

    def test_escapes_and_compact_hex(self):
        self.assertEqual(parse_hex_bytes(r"\x48\x65\x6c\x6c\x6f"), b"Hello")
        self.assertEqual(parse_hex_bytes("68656c6c6f"), b"hello")

    def test_hexdump_ignores_the_address(self):
        self.assertEqual(parse_hex_bytes("00000000: 48 65 6c 6c 6f"), b"Hello")
        self.assertEqual(parse_hex_bytes("00000000  68 65 6c 6c 6f"), b"hello")
        gutter = "00000000: 48 65 6c 6c 6f 20 44 65  63 6f 64 65 72  |Hello Decoder|"
        self.assertEqual(parse_hex_bytes(gutter), b"Hello Decoder")

    def test_odd_hex_is_rejected(self):
        with self.assertRaises(ValueError):
            parse_hex_bytes("48656c6c6")

    def test_invalid_utf8_does_not_insert_a_replacement(self):
        text = Converters.hex_to_text("ff")
        self.assertNotIn("\ufffd", text)
        self.assertEqual(text, "ÿ")
        self.assertIn("latin-1", Converters.last_note or "")

    def test_bom_is_reported_and_not_left_in_the_text(self):
        text = Converters.hex_to_text("efbbbf41")
        self.assertEqual(text, "A")
        self.assertIn("BOM", Converters.last_note or "")

    def test_spaced_7bit_binary_is_one_byte_each(self):
        # 'h' and 'e' without the leading zero bit
        self.assertEqual(parse_binary_bytes("1101000 1100101"), b"he")

    def test_short_continuous_bits_are_not_padded(self):
        with self.assertRaises(ValueError):
            parse_binary_bytes("11010001100101")

    def test_binary_to_base64_and_back(self):
        # 'Hi' is 01001000 01101001
        self.assertEqual(Converters.binary_to_base64("01001000 01101001"), "SGk=")
        self.assertEqual(Converters.binary_to_base64("0b0100100001101001"), "SGk=")
        self.assertEqual(
            Converters.base64_to_binary("SGk="),
            "01001000 01101001",
        )

    def test_xor_hex_key_keeps_a_single_byte(self):
        # 0x41 used to become 0x00 0x41 because the 0 in 0x survived
        out = Converters.xor_crypt("A", "0x41", key_is_hex=True, output="hex")
        self.assertEqual(out, "00")


class AsciiListTests(unittest.TestCase):
    def test_decimal_list_still_decodes(self):
        nums, err = parse_number_list("[72, 101, 108, 108, 111]")
        self.assertIsNone(err)
        self.assertEqual(Converters.numbers_to_text(nums), "Hello")

    def test_prefixed_hex_list_has_no_extra_null(self):
        nums, err = parse_number_list("0x48 0x65 0x6c 0x6c 0x6f")
        self.assertIsNone(err)
        self.assertEqual(nums, [0x48, 0x65, 0x6C, 0x6C, 0x6F])

    def test_compact_hex_token_splits_into_bytes(self):
        nums, err = parse_number_list("DEADBEEF", base="hex")
        self.assertIsNone(err)
        self.assertEqual(nums, [0xDE, 0xAD, 0xBE, 0xEF])

    def test_wide_value_is_a_code_point(self):
        self.assertEqual(Converters.numbers_to_text([0x1F600]), "\U0001f600")


class CipherTests(unittest.TestCase):
    def test_rot8_round_trip(self):
        self.assertEqual(Converters.rot_n("hello", 8), "pmttw")
        self.assertEqual(Converters.rot_n("pmttw", -8), "hello")

    def test_rot47_atbash_and_reverse_are_their_own_inverse(self):
        sample = "Hello, Decoder!"
        self.assertEqual(Converters.rot47(Converters.rot47(sample)), sample)
        self.assertEqual(Converters.atbash(Converters.atbash(sample)), sample)
        self.assertEqual(Converters.reverse_text(Converters.reverse_text(sample)), sample)

    def test_morse_and_a1z26_round_trip(self):
        self.assertEqual(Converters.from_morse(Converters.to_morse("HELLO")), "HELLO")
        self.assertEqual(Converters.a1z26_decode(Converters.a1z26_encode("HELLO")), "HELLO")

    def test_vigenere_round_trip(self):
        cipher = Converters.vigenere("ATTACKATDAWN", "KEY", decrypt=False)
        self.assertEqual(Converters.vigenere(cipher, "KEY", decrypt=True), "ATTACKATDAWN")


class ChartTests(unittest.TestCase):
    def test_character_decimal_and_hex_lookup(self):
        as_char = lookup("A")
        self.assertIn("0x41", as_char)
        self.assertIn("65", as_char)
        both = lookup("41")
        self.assertIn("As decimal 41", both)
        self.assertIn("As hex 0x41", both)
        self.assertIn("LATIN CAPITAL LETTER A", both)

    def test_named_control(self):
        self.assertIn("0x0A", lookup("newline"))
        self.assertIn("LF", lookup("newline"))


if __name__ == "__main__":
    unittest.main()
