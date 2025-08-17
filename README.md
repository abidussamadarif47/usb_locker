# USB Locker

A simple cross‑platform GUI tool (Tkinter) to **LOCK** (encrypt) or **UNLOCK** (decrypt) a folder (e.g., your USB drive root) using **AES‑256‑GCM** with **scrypt** key derivation.

> **Warning:** Test with dummy files first. If you forget your password, **data is unrecoverable**. Use at your own risk.

## Features
- Per‑file encryption into `*.ulock` containers (salt+nonce per file).
- Scrypt (N=16384, r=8, p=1) → 32‑byte key.
- AES‑GCM authenticated encryption (integrity protection).
- Simple GUI with progress bar and live log.
- Skips hidden files/dirs by default.

## Installation
1. **Python 3.9+** recommended.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Run
```bash
python main.py
```

Select your USB drive **root folder**, set a **password/PIN**, choose **LOCK** or **UNLOCK**, then **Start**.

## Packaging (Standalone EXE/App)
Use PyInstaller:
```bash
pip install pyinstaller
pyinstaller --noconfirm --onefile --windowed --name USBLockItClone main.py
```
The executable will be in `dist/`.

## File Format (`.ulock`)
```
[4]  magic = "ULCK"
[1]  version = 0x01
[16] salt
[12] nonce
[4]  aad_len (big‑endian)
[aad_len] aad = original filename (utf‑8)
[..] ciphertext (AES‑GCM)
```

## Notes & Limitations
- This reference implementation **reads entire files into memory**. For very large files (>1GB), switch to a chunked design (e.g., using AES‑GCM‑SIV or streaming construction with per‑chunk AD).
- Renames on decrypt if a file with the original name already exists (adds `_restoredN`).
- This app **does not** modify partition tables or low‑level device settings. It simply encrypts/decrypts files.
- Keep backups. No password recovery exists.

## Security Recommendations
- Use a strong password. Prefer a passphrase (4–6 random words).
- Keep your app/executable safe; attackers with full device access could tamper with binaries.
- Consider code‑signing your build if distributing.

## License
MIT
