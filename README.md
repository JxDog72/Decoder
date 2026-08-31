# Decoder

Local desktop encode / decode / hash toolkit. Nothing is uploaded. No account.

**Windows 10/11 and Linux.** License: [MIT](LICENSE).

---

## Windows

Python 3.10+ on PATH.

```bat
Run-Decoder.bat
```

That installs `customtkinter` if needed, then starts the GUI (no leftover console window).

Or:

```bat
python -m pip install -r requirements.txt
python app.py
```

---

## Linux

```bash
sudo apt install python3 python3-tk python3-pip
chmod +x run-decoder.sh
./run-decoder.sh
```

Or: `python3 -m pip install -r requirements.txt && python3 app.py`

---

## Tabs

| Tab | What it does |
|-----|----------------|
| **ASCII Lists** | Number lists ↔ text (brackets, commas, `0x`, `\x`, Python assignments) |
| **Base / Encodings** | Base64, URL-safe Base64, Base32, Base85, Ascii85 |
| **Hex / Binary** | Text ↔ hex (spaced/compact) ↔ binary |
| **URL / HTML** | Percent-encoding and HTML entities |
| **Ciphers** | ROT/Caesar, ROT47, Atbash, reverse, Morse, A1Z26 |
| **Crypto** | Vigenère, XOR (text/hex key), Rail Fence |
| **Hash Check** | Paste a hash + candidate text, or verify a downloaded file |
| **Unicode** | Code points and byte summary |
| **Try All** | One paste → many decoders at once |

Every text pane has **Paste / Copy / Clear**, plus a right-click menu.

---

## Hash checker

This does **not** reverse a hash into unknown plaintext. It tells you whether a candidate string (or a file) produces that digest.

### Text

1. Paste the hex digest on the left (or a `sha256sum` line, or `SHA256: …`).
2. Paste the candidate plaintext on the right.
3. **Verify hash** (`auto` picks the algorithm from digest length).

If you paste them in the wrong boxes, Verify still figures it out.

**Hash candidate** writes the digest of the right-hand text into the hash box. **Hash all algos** lists MD5, SHA-1/2/3, and BLAKE2.

### Downloaded file

1. Source = **File** → **Browse file…**
2. Paste the publisher’s checksum
3. **Verify hash**

Files are stream-hashed (1 MB chunks). Green **MATCH** / red **NO MATCH**.

---

## Crypto notes

Vigenère, XOR, and Rail Fence are for puzzles and learning — not a substitute for modern encryption.
