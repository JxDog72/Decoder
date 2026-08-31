# Decoder

Local desktop app: encode and decode text, try common ciphers, and check hashes. Nothing is uploaded. No account.

![Decoder main window](https://raw.githubusercontent.com/JxDog72/Decoder/screenshots/mainView.png)

**Windows 10/11 and Linux.** License: [MIT](LICENSE).

---

## Windows

Python 3.10+ on PATH.

```bat
Run-Decoder.bat
```

That installs what it needs, then starts the window (no leftover console).

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
| **ASCII Lists** | Number lists ↔ text (brackets, commas, hex, Python-style lists) |
| **Base / Encodings** | Base64, URL-safe Base64, Base32, Base85, Ascii85 |
| **Hex / Binary** | Text ↔ hex ↔ binary |
| **URL / HTML** | URL encoding and HTML entities |
| **Ciphers** | ROT/Caesar, ROT47, Atbash, reverse, Morse, A1Z26 |
| **Crypto** | Vigenère, XOR, Rail Fence (puzzles / learning only) |
| **Hash Check** | Paste a hash and a candidate string, or check a downloaded file |
| **Unicode** | Code points and a short byte summary |
| **Try All** | One paste, several decoders at once |

Every text box has **Paste / Copy / Clear**, plus a right-click menu.

---

## Hash checker

This does **not** turn a hash back into unknown text. It only tells you whether a candidate string (or a file) matches that hash.

### Text

1. Paste the hash on the left (hex is fine, or `SHA256: …`).
2. Paste the candidate text on the right.
3. **Verify hash** (`auto` picks the type from the hash length).

If you paste them in the wrong boxes, Verify still figures it out.

**Hash candidate** writes the hash of the right-hand text into the left box. **Hash all algos** lists MD5, SHA-1/2/3, and BLAKE2.

### Downloaded file

1. Source = **File** → **Browse file…**
2. Paste the published checksum
3. **Verify hash**

Large files are read in chunks so they do not need to fit in RAM. Green **MATCH** / red **NO MATCH**.

---

## Crypto notes

Vigenère, XOR, and Rail Fence are for puzzles and learning — not a stand-in for real encryption.
