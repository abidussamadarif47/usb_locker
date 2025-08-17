
import os
import sys
import threading
import traceback
import base64
import secrets
from dataclasses import dataclass
from typing import List, Optional, Tuple
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
APP_NAME = "USB LockIt"
ENC_EXT = ".ulock"
SALT_LEN = 16
NONCE_LEN = 12
def derive_key(password: str, salt: bytes) -> bytes:
    # scrypt parameters: moderately strong defaults; adjust time/memory as needed
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(password.encode("utf-8"))

def aesgcm_encrypt(key: bytes, plaintext: bytes, nonce: bytes, aad: Optional[bytes]=None) -> bytes:
    return AESGCM(key).encrypt(nonce, plaintext, aad)

def aesgcm_decrypt(key: bytes, ciphertext: bytes, nonce: bytes, aad: Optional[bytes]=None) -> bytes:
    return AESGCM(key).decrypt(nonce, ciphertext, aad)

def is_hidden(path: str) -> bool:
    name = os.path.basename(path)
    if name.startswith('.'):
        return True

    try:
        import ctypes
        attrs = ctypes.windll.kernel32.GetFileAttributesW(str(path))
        if attrs != -1 and (attrs & 2):  # FILE_ATTRIBUTE_HIDDEN = 0x2
            return True
    except Exception:
        pass
    return False

def human_bytes(n: int) -> str:
    for unit in ['B','KB','MB','GB','TB']:
        if n < 1024:
            return f"{n:.2f} {unit}"
        n /= 1024
    return f"{n:.2f} PB"

def gather_files(root: str, encrypt_mode: bool) -> List[str]:
    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        # skip hidden dirs
        dirnames[:] = [d for d in dirnames if not d.startswith('.')]
        for fname in filenames:
            fpath = os.path.join(dirpath, fname)
            if is_hidden(fpath):
                continue
            # Skip our own app files by extension rule
            if encrypt_mode:
                # skip already encrypted files
                if fname.endswith(ENC_EXT):
                    continue
            else:
                # decrypt mode: only encrypted files
                if not fname.endswith(ENC_EXT):
                    continue
            files.append(fpath)
    return files



@dataclass
class TaskConfig:
    root: str
    password: str
    mode: str  # "lock" or "unlock"
    delete_original: bool = True

class Locker:
    def __init__(self, ui_logger):
        self.ui_logger = ui_logger
        self.stop_flag = False

    def log(self, msg: str):
        if self.ui_logger:
            self.ui_logger(msg)

    def stop(self):
        self.stop_flag = True

    def lock_file(self, path: str, password: str) -> Tuple[bool, Optional[str]]:
        try:
            with open(path, "rb") as f:
                data = f.read()
            salt = secrets.token_bytes(SALT_LEN)
            key = derive_key(password, salt)
            nonce = secrets.token_bytes(NONCE_LEN)
            aad = os.path.basename(path).encode("utf-8")
            ct = aesgcm_encrypt(key, data, nonce, aad)
            out_path = path + ENC_EXT
            
            magic = b"ULCK"
            version = b"\x01"
            aad_len = len(aad).to_bytes(4, "big")
            blob = magic + version + salt + nonce + aad_len + aad + ct
            with open(out_path, "wb") as f:
                f.write(blob)
            if os.path.exists(out_path) and os.path.getsize(out_path) > 0:
                if os.path.exists(path):
                    os.remove(path)
            return True, out_path
        except Exception as e:
            return False, f"{path}: {e}"

    def unlock_file(self, path: str, password: str) -> Tuple[bool, Optional[str]]:
        try:
            with open(path, "rb") as f:
                blob = f.read()
            # parse
            if not blob.startswith(b"ULCK"):
                raise ValueError("Invalid file format (magic)")
            idx = 4
            version = blob[idx:idx+1]; idx += 1
            if version != b"\x01":
                raise ValueError("Unsupported version")
            salt = blob[idx:idx+SALT_LEN]; idx += SALT_LEN
            nonce = blob[idx:idx+NONCE_LEN]; idx += NONCE_LEN
            aad_len = int.from_bytes(blob[idx:idx+4], "big"); idx += 4
            aad = blob[idx:idx+aad_len]; idx += aad_len
            ct = blob[idx:]
            key = derive_key(password, salt)
            pt = aesgcm_decrypt(key, ct, nonce, aad)
            
            original_name = aad.decode("utf-8", errors="ignore")
            out_path = os.path.join(os.path.dirname(path), original_name)
            
            base, ext = os.path.splitext(out_path)
            counter = 1
            while os.path.exists(out_path):
                out_path = f"{base}_restored{counter}{ext}"
                counter += 1
            with open(out_path, "wb") as f:
                f.write(pt)
        
            os.remove(path)
            return True, out_path
        except Exception as e:
            return False, f"{path}: {e}"

    def run_task(self, cfg: TaskConfig, progress_cb=None):
        mode = cfg.mode
        targets = gather_files(cfg.root, encrypt_mode=(mode=="lock"))
        total = len(targets)
        if total == 0:
            self.log("No matching files found.")
            return

        self.log(f"Found {total} file(s) to process.")
        done = 0
        for fpath in targets:
            if self.stop_flag:
                self.log("Operation cancelled.")
                break
            rel = os.path.relpath(fpath, cfg.root)
            try:
                if mode == "lock":
                    ok, info = self.lock_file(fpath, cfg.password)
                else:
                    ok, info = self.unlock_file(fpath, cfg.password)
                if ok:
                    self.log(f"✔ {rel}")
                else:
                    self.log(f"✖ {rel}  ->  {info}")
            except Exception as e:
                self.log(f"✖ {rel}  ->  {e}")
            finally:
                done += 1
                if progress_cb:
                    progress_cb(done, total)
        self.log("Done.")
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_NAME)
        self.geometry("680x520")
        self.resizable(False, False)

        self.selected_dir = tk.StringVar()
        self.password = tk.StringVar()
        self.mode = tk.StringVar(value="lock")

        self.locker = Locker(self.append_log)
        self.worker_thread: Optional[threading.Thread] = None

        self.create_widgets()

    def create_widgets(self):
        pad = 10

        frm_top = ttk.LabelFrame(self, text="Target folder (USB root recommended)")
        frm_top.pack(fill="x", padx=pad, pady=(pad, 5))

        ent = ttk.Entry(frm_top, textvariable=self.selected_dir)
        ent.pack(side="left", fill="x", expand=True, padx=(pad, 5), pady=pad)

        btn_browse = ttk.Button(frm_top, text="Browse…", command=self.browse_dir)
        btn_browse.pack(side="left", padx=pad, pady=pad)

        frm_pw = ttk.LabelFrame(self, text="Password / PIN")
        frm_pw.pack(fill="x", padx=pad, pady=5)

        ent_pw = ttk.Entry(frm_pw, textvariable=self.password, show="•")
        ent_pw.pack(fill="x", padx=pad, pady=pad)

        frm_mode = ttk.Frame(self)
        frm_mode.pack(fill="x", padx=pad, pady=5)
        ttk.Radiobutton(frm_mode, text="LOCK (encrypt)", variable=self.mode, value="lock").pack(side="left", padx=(0, 15))
        ttk.Radiobutton(frm_mode, text="UNLOCK (decrypt)", variable=self.mode, value="unlock").pack(side="left")

        frm_actions = ttk.Frame(self)
        frm_actions.pack(fill="x", padx=pad, pady=5)

        self.btn_start = ttk.Button(frm_actions, text="Start", command=self.start_task)
        self.btn_start.pack(side="left", padx=(0, 10))

        self.btn_cancel = ttk.Button(frm_actions, text="Cancel", command=self.cancel_task, state="disabled")
        self.btn_cancel.pack(side="left")

        frm_prog = ttk.Frame(self)
        frm_prog.pack(fill="x", padx=pad, pady=5)
        self.progress = ttk.Progressbar(frm_prog, orient="horizontal", mode="determinate")
        self.progress.pack(fill="x", padx=pad, pady=(5,10))

        frm_log = ttk.LabelFrame(self, text="Log")
        frm_log.pack(fill="both", expand=True, padx=pad, pady=(5, pad))

        self.txt = tk.Text(frm_log, height=16, wrap="word")
        self.txt.pack(fill="both", expand=True, padx=pad, pady=pad)

        self.append_log("Select your USB drive folder, enter a strong password, then click Start.")

    def browse_dir(self):
        d = filedialog.askdirectory(title="Select USB root folder")
        if d:
            self.selected_dir.set(d)

    def set_ui_busy(self, busy: bool):
        state = "disabled" if busy else "normal"
        self.btn_start.config(state="disabled" if busy else "normal")
        self.btn_cancel.config(state="normal" if busy else "disabled")

    def start_task(self):
        root = self.selected_dir.get().strip()
        pw = self.password.get()
        mode = self.mode.get()

        if not root or not os.path.isdir(root):
            messagebox.showerror(APP_NAME, "Please select a valid folder (USB root).")
            return
        if not pw:
            messagebox.showerror(APP_NAME, "Please enter a password / PIN.")
            return
        self.append_log(f"Mode: {mode.upper()}  |  Folder: {root}")
        self.progress["value"] = 0
        self.set_ui_busy(True)

        cfg = TaskConfig(root=root, password=pw, mode=mode)
        self.worker_thread = threading.Thread(target=self._thread_run, args=(cfg,), daemon=True)
        self.worker_thread.start()

    def _thread_run(self, cfg: TaskConfig):
        try:
            targets = gather_files(cfg.root, encrypt_mode=(cfg.mode=="lock"))
            total = max(1, len(targets))
            def on_prog(done, tot):
                self.progress["maximum"] = tot
                self.progress["value"] = done
            self.locker.run_task(cfg, progress_cb=on_prog)
        except Exception as e:
            self.append_log("Error: " + str(e))
            self.append_log(traceback.format_exc())
        finally:
            self.set_ui_busy(False)

    def cancel_task(self):
        self.locker.stop()
        self.append_log("Cancellation requested…")

    def append_log(self, msg: str):
        self.txt.insert("end", msg + "\n")
        self.txt.see("end")
        self.update_idletasks()

def main():
    app = App()
    app.mainloop()

if __name__ == "__main__":
    main()
