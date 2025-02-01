#!/usr/bin/env python3
"""
SecureFileEncryptor_v4.4.3.py
Version: v4.4.3

A simplified GUI file encryption/decryption tool that uses AES-GCM in both single-shot
and chunked modes. This version reverts to a simpler file-selection model:
users click a button to open the native file picker and select the files they want to process.
In addition, encryption/decryption tasks run in separate threads, and a progress bar 
provides real-time feedback so that the window remains responsive.

Improvements in this version:
  - Simplified file selection using a native file picker.
  - Granular per-chunk MACs in chunked mode.
  - Enhanced input validations to reject symbolic links and files in sensitive directories.
  - Multithreading for long-running encryption/decryption processes.
  - Progress indicators (progress bar) updated during file processing.
  - Updated version to v4.4.3.

References:
  Cryptography.io. “AES-GCM.” Cryptography, 2021, https://cryptography.io/en/latest/hazmat/primitives/aead/.
  Gutmann, Peter. “Secure Deletion of Data from Magnetic and Solid-State Memory.” USENIX, 1996, https://www.usenix.org/legacy/publications/library/proceedings/sec96/full_papers/gutmann/gutmann.pdf.
  NIST. “Digital Identity Guidelines: Authentication and Lifecycle Management.” NIST SP 800-63B, 2017, https://doi.org/10.6028/NIST.SP.800-63b.
  OWASP. “File Upload Cheat Sheet.” OWASP Cheat Sheet Series, https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html.
"""

import os
import tempfile
import logging
import hmac
import hashlib
import secrets
import base64
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from threading import Thread

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Program metadata
PROGRAM_NAME = "SecureFileEncryptor"
VERSION = "v4.4.3"

# Constants for chunked processing
CHUNK_THRESHOLD = 10 * 1024 * 1024  # 10 MB threshold
CHUNK_SIZE = 1024 * 1024            # 1 MB per chunk
PBKDF2_ITERATIONS = 200_000         # Iterations for PBKDF2
NONCE_COUNTER_MAX = 2**32 - 1       # Maximum 4-byte counter value

# Configure logging: log only non-sensitive error messages.
logging.basicConfig(
    filename="file_encryptor_v4.4.3.log",
    level=logging.ERROR,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
try:
    os.chmod("file_encryptor_v4.4.3.log", 0o600)
except OSError as e:
    logging.warning("Could not set log file permissions: " + str(e))

def update_chain(chaining_value: bytes, token: bytes, seq_bytes: bytes) -> bytes:
    """Update chaining value: new_value = SHA256(chaining_value || token || seq_bytes)."""
    return hashlib.sha256(chaining_value + token + seq_bytes).digest()

def zeroize_bytearray(data: bytearray):
    """Overwrite a bytearray with zeros."""
    for i in range(len(data)):
        data[i] = 0

def validate_header_fields(header_lines, required_fields):
    """Ensure all required header fields are present in header_lines."""
    header_dict = {}
    for line in header_lines:
        if b":" not in line:
            continue
        try:
            field, value = line.split(b":", 1)
            header_dict[field.strip()] = value.strip()
        except ValueError:
            continue
    missing = [field for field in required_fields if field not in header_dict]
    if missing:
        raise ValueError("Missing required header fields: " + ", ".join([m.decode() for m in missing]))
    return header_dict

def canonicalize_path(path: str) -> str:
    """Return the canonicalized absolute path."""
    return os.path.realpath(os.path.abspath(path))

def is_safe_file(file: str) -> bool:
    """Check that the file is not a symbolic link and is not in a system-sensitive directory."""
    file = canonicalize_path(file)
    if os.path.islink(file):
        return False
    sensitive_dirs = ["/etc", "/bin", "/usr", "/sbin", "/var"]
    for sd in sensitive_dirs:
        if file.startswith(sd + os.sep):
            return False
    return True

class FileEncryptorApp(tk.Tk):
    def __init__(self):
        super().__init__()
        # Increase window size with a buffer zone.
        self.geometry("900x650")
        self.minsize(900, 650)
        self.title(f"{PROGRAM_NAME} {VERSION}")
        # Maintain a list of selected files.
        self.selected_files = []
        self.create_widgets()

    def create_widgets(self):
        # File selection frame.
        file_frame = tk.Frame(self, padx=10, pady=10)
        file_frame.pack(fill=tk.X)
        tk.Button(file_frame, text="Select File(s)", command=self.select_files).pack(side=tk.LEFT, padx=5)
        tk.Button(file_frame, text="Clear Selection", command=self.clear_selection).pack(side=tk.LEFT, padx=5)
        
        # Listbox to display selected files.
        list_frame = tk.Frame(self, padx=10, pady=10)
        list_frame.pack(fill=tk.BOTH, expand=True)
        self.file_listbox = tk.Listbox(list_frame, selectmode=tk.MULTIPLE)
        self.file_listbox.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)
        scrollbar = tk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.file_listbox.yview)
        self.file_listbox.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Key input frame.
        key_frame = tk.Frame(self, padx=10, pady=5)
        key_frame.pack(fill=tk.X)
        tk.Label(key_frame, text="Passphrase:").grid(row=0, column=0, sticky="e", padx=5)
        self.key_entry = tk.Entry(key_frame, width=40, show="*")
        self.key_entry.grid(row=0, column=1, padx=5)
        tk.Label(key_frame, text="Confirm Passphrase:").grid(row=1, column=0, sticky="e", padx=5)
        self.confirm_entry = tk.Entry(key_frame, width=40, show="*")
        self.confirm_entry.grid(row=1, column=1, padx=5)
        tk.Button(key_frame, text="Generate Random Key", command=self.generate_key).grid(row=0, column=2, rowspan=2, padx=5)

        # Options frame.
        options_frame = tk.Frame(self, padx=10, pady=5)
        options_frame.pack(fill=tk.X)
        self.delete_var = tk.BooleanVar()
        tk.Checkbutton(options_frame, text="Securely delete original file", variable=self.delete_var).pack(side=tk.LEFT, padx=5)

        # Action buttons frame.
        action_frame = tk.Frame(self, padx=10, pady=10)
        action_frame.pack()
        tk.Button(action_frame, text="Encrypt Files", command=self.start_encrypt_thread).pack(side=tk.LEFT, padx=5)
        tk.Button(action_frame, text="Decrypt Files", command=self.start_decrypt_thread).pack(side=tk.LEFT, padx=5)
        tk.Button(action_frame, text="Securely Erase Files", command=self.secure_erase_files).pack(side=tk.LEFT, padx=5)

        # Progress bar frame.
        progress_frame = tk.Frame(self, padx=10, pady=10)
        progress_frame.pack(fill=tk.X)
        self.progress_bar = ttk.Progressbar(progress_frame, orient="horizontal", mode="determinate", maximum=100)
        self.progress_bar.pack(fill=tk.X)
        
    def select_files(self):
        """Open a native file picker to select one or more files."""
        files = filedialog.askopenfilenames(title="Select file(s) to process")
        if files:
            for f in files:
                safe_path = canonicalize_path(f)
                if not is_safe_file(safe_path):
                    messagebox.showerror("Unsafe File", f"File {safe_path} is a symbolic link or located in a sensitive directory.")
                    continue
                if safe_path not in self.selected_files:
                    self.selected_files.append(safe_path)
                    self.file_listbox.insert(tk.END, safe_path)

    def clear_selection(self):
        """Clear the current file selection."""
        self.selected_files = []
        self.file_listbox.delete(0, tk.END)

    def generate_key(self):
        try:
            raw_key = AESGCM.generate_key(bit_length=256)
            key_b64 = base64.urlsafe_b64encode(raw_key).decode('utf-8')
            self.key_entry.delete(0, tk.END)
            self.key_entry.insert(0, key_b64)
            self.confirm_entry.delete(0, tk.END)
            self.confirm_entry.insert(0, key_b64)
            if messagebox.askyesno("Clipboard Confirmation",
                                   "Copy generated key to clipboard? WARNING: The clipboard is a shared resource."):
                self.clipboard_clear()
                self.clipboard_append(key_b64)
            popup = tk.Toplevel(self)
            popup.title("Generated Key")
            tk.Label(popup,
                     text="Your new key (copy to clipboard if desired).\nSave this key securely; you will need it to decrypt your files:").pack(padx=10, pady=10)
            key_display = tk.Entry(popup, width=50)
            key_display.insert(0, key_b64)
            key_display.config(state="readonly")
            key_display.pack(padx=10, pady=10)
            tk.Button(popup, text="Close", command=popup.destroy).pack(pady=10)
            key_buffer = bytearray(raw_key)
            zeroize_bytearray(key_buffer)
        except Exception as e:
            logging.exception("Key generation failed")
            messagebox.showerror("Error", "Key generation failed. Please try again.")

    def confirm_overwrite(self, filename):
        if os.path.exists(filename):
            return messagebox.askyesno("File Exists", f"File {os.path.basename(filename)} already exists. Overwrite?")
        return True

    def secure_delete(self, file_path, passes=3):
        try:
            if os.path.exists(file_path):
                length = os.path.getsize(file_path)
                with open(file_path, "r+b", buffering=0) as f:
                    for _ in range(passes):
                        f.seek(0)
                        for offset in range(0, length, 4096):
                            block_size = min(4096, length - offset)
                            f.write(os.urandom(block_size))
                        f.flush()
                        os.fsync(f.fileno())
                os.remove(file_path)
        except OSError as e:
            logging.exception("Secure deletion failed for %s", file_path)
            messagebox.showwarning("Warning", f"Secure deletion failed for {os.path.basename(file_path)}.")
    
    def secure_erase_files(self):
        if not self.selected_files:
            messagebox.showinfo("No Files Selected", "Please select file(s) to securely erase.")
            return
        confirm = messagebox.askyesno("Confirm Secure Erase",
                                      f"Are you sure you want to permanently erase the selected {len(self.selected_files)} file(s)? This action cannot be undone.")
        if not confirm:
            return
        for file_path in self.selected_files:
            try:
                self.secure_delete(file_path)
            except Exception:
                logging.exception("Failed to securely erase file: %s", file_path)
        messagebox.showinfo("Secure Deletion Complete", "Selected files have been securely erased.")
    
    def _derive_key(self, key_str: str, key_salt: bytes = None) -> (bytearray, bytes):
        """
        Always derive the key using PBKDF2.
        When encrypting, a random salt is generated and returned.
        When decrypting, the salt is provided from the header.
        
        NOTE: Python’s memory management does not guarantee complete zeroization.
        For high-security environments, consider using a lower-level implementation.
        """
        if not key_str:
            raise ValueError("Key string is empty.")
        if key_salt is None:
            key_salt = os.urandom(16)
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=key_salt,
                iterations=PBKDF2_ITERATIONS,
            )
            derived_key = kdf.derive(key_str.encode('utf-8'))
        except Exception as e:
            logging.exception("PBKDF2 key derivation failed")
            raise ValueError("Key derivation error: " + str(e))
        return bytearray(derived_key), key_salt

    # ----------------- Multithreaded Encryption -----------------
    def start_encrypt_thread(self):
        Thread(target=self.encrypt_files_thread, daemon=True).start()

    def encrypt_files_thread(self):
        # Reset progress bar at start.
        self.progress_bar.after(0, lambda: self.progress_bar.config(value=0))
        if not self.selected_files:
            self.progress_bar.after(0, lambda: messagebox.showwarning("No Files Selected", "Please select file(s) to encrypt."))
            return
        key_str = self.key_entry.get().strip()
        confirm_str = self.confirm_entry.get().strip()
        if not key_str or not confirm_str:
            self.progress_bar.after(0, lambda: messagebox.showwarning("Missing Key", "Please enter and confirm the passphrase."))
            return
        if key_str != confirm_str:
            self.progress_bar.after(0, lambda: messagebox.showerror("Passphrase Mismatch", "The passphrase and its confirmation do not match."))
            return
        try:
            key, key_salt = self._derive_key(key_str)
            aesgcm = AESGCM(bytes(key))
        except ValueError as e:
            logging.exception("Key derivation failed")
            self.progress_bar.after(0, lambda: messagebox.showerror("Invalid Passphrase", "The provided passphrase is invalid: " + str(e)))
            return

        total_files = len(self.selected_files)
        file_counter = 0
        for file in self.selected_files:
            file = canonicalize_path(file)
            if not is_safe_file(file):
                self.progress_bar.after(0, lambda: messagebox.showerror("Unsafe File", f"File {file} is not safe for processing."))
                continue
            directory = os.path.dirname(file)
            try:
                file_size = os.path.getsize(file)
            except OSError as e:
                logging.error("Failed to get file size for %s: %s", file, str(e))
                self.progress_bar.after(0, lambda: messagebox.showerror("Error", f"Failed to access file size for {os.path.basename(file)}."))
                continue
            new_file = file + ".enc"
            if not self.confirm_overwrite(new_file):
                continue
            temp_path = None
            try:
                with tempfile.NamedTemporaryFile(dir=directory, delete=False) as temp_file:
                    temp_path = temp_file.name
                    os.chmod(temp_path, 0o600)
                    if file_size < CHUNK_THRESHOLD:
                        nonce = os.urandom(12)
                        header_lines = [
                            f"{PROGRAM_NAME} {VERSION}".encode(),
                            b"MODE:SINGLE"
                        ]
                        header_lines.append(b"KEYSALT:" + key_salt.hex().encode())
                        header_lines.append(b"NONCE:" + nonce.hex().encode())
                        header_data = b"\n".join(header_lines)
                        with open(file, "rb") as in_file:
                            plaintext = in_file.read()
                        ciphertext = aesgcm.encrypt(nonce, plaintext, header_data)
                        temp_file.write(header_data + b"\n\n" + ciphertext)
                        # For single-shot files, set progress to 100% immediately.
                        self.progress_bar.after(0, lambda: self.progress_bar.config(value=100))
                    else:
                        nonce_prefix = os.urandom(8)
                        hkdf_salt = os.urandom(16)
                        hkdf_info = os.urandom(16)
                        initial_chain = os.urandom(32)
                        header_lines = [
                            f"{PROGRAM_NAME} {VERSION}".encode(),
                            b"MODE:CHUNKED"
                        ]
                        header_lines.append(b"KEYSALT:" + key_salt.hex().encode())
                        header_lines.append(b"NONCE_PREFIX:" + nonce_prefix.hex().encode())
                        header_lines.append(b"HKDF_SALT:" + hkdf_salt.hex().encode())
                        header_lines.append(b"HKDF_INFO:" + hkdf_info.hex().encode())
                        header_lines.append(b"CHAIN:" + initial_chain.hex().encode())
                        header_data = b"\n".join(header_lines) + b"\n"
                        temp_file.write(header_data)
                        hkdf = HKDF(
                            algorithm=hashes.SHA256(),
                            length=32,
                            salt=hkdf_salt,
                            info=hkdf_info
                        )
                        hmac_key = hkdf.derive(bytes(key))
                        per_chunk_mac_key = hmac.new(hmac_key, b"CHUNK_MAC", hashlib.sha256).digest()
                        global_hmac = hmac.new(hmac_key, digestmod=hashlib.sha256)
                        global_hmac.update(header_data)
                        header_hash = hashlib.sha256(header_data).digest()
                        seq = 0
                        chaining_value = initial_chain
                        bytes_read = 0
                        with open(file, "rb") as in_file:
                            while True:
                                chunk = in_file.read(CHUNK_SIZE)
                                if not chunk:
                                    break
                                bytes_read += len(chunk)
                                progress = int((bytes_read / file_size) * 100)
                                # Update progress in a thread-safe manner.
                                self.progress_bar.after(0, lambda p=progress: self.progress_bar.config(value=p))
                                if seq > NONCE_COUNTER_MAX:
                                    raise ValueError("File is too large; nonce counter overflow.")
                                seq_bytes = f"{seq:08d}".encode("utf-8")
                                nonce = nonce_prefix + seq.to_bytes(4, byteorder='big')
                                chunk_length = len(chunk).to_bytes(4, byteorder='big')
                                aad = header_hash + b"SEQ:" + seq_bytes + b"LENGTH:" + chunk_length
                                token = aesgcm.encrypt(nonce, chunk, aad)
                                per_chunk_mac = hmac.new(per_chunk_mac_key, token, hashlib.sha256).hexdigest().encode()
                                line = (b"SEQ:" + seq_bytes +
                                        b" CHAIN:" + chaining_value.hex().encode() +
                                        b" LENGTH:" + chunk_length +
                                        b" TOKEN:" + token +
                                        b" CHUNKMAC:" + per_chunk_mac)
                                temp_file.write(line + b"\n")
                                global_hmac.update(line + b"\n")
                                chaining_value = update_chain(chaining_value, token, seq_bytes)
                                seq += 1
                        hmac_line = b"HMAC:" + global_hmac.hexdigest().encode() + b"\n"
                        temp_file.write(hmac_line)
                        # Ensure progress is complete after processing the file.
                        self.progress_bar.after(0, lambda: self.progress_bar.config(value=100))
                os.replace(temp_path, new_file)
                self.progress_bar.after(0, lambda: messagebox.showinfo("Success", f"Encrypted: {os.path.basename(new_file)}"))
                if self.delete_var.get():
                    self.secure_delete(file)
            except Exception as e:
                logging.error("Encryption failed for %s: %s", file, str(e))
                self.progress_bar.after(0, lambda: messagebox.showerror("Error", f"Encryption failed for {os.path.basename(file)}. {str(e)}"))
            finally:
                if temp_path and os.path.exists(temp_path):
                    try:
                        os.remove(temp_path)
                    except Exception:
                        logging.warning("Failed to remove temporary file: %s", temp_path)
            file_counter += 1
            # Optionally, update overall progress across files.
            overall_progress = int((file_counter / total_files) * 100)
            self.progress_bar.after(0, lambda p=overall_progress: self.progress_bar.config(value=p))
        zeroize_bytearray(key)
        self.key_entry.after(0, lambda: self.key_entry.delete(0, tk.END))
        self.confirm_entry.after(0, lambda: self.confirm_entry.delete(0, tk.END))
    
    # ----------------- Multithreaded Decryption -----------------
    def start_decrypt_thread(self):
        Thread(target=self.decrypt_files_thread, daemon=True).start()

    def decrypt_files_thread(self):
        self.progress_bar.after(0, lambda: self.progress_bar.config(value=0))
        if not self.selected_files:
            self.progress_bar.after(0, lambda: messagebox.showwarning("No Files Selected", "Please select file(s) to decrypt."))
            return
        key_str = self.key_entry.get().strip()
        confirm_str = self.confirm_entry.get().strip()
        if not key_str:
            self.progress_bar.after(0, lambda: messagebox.showwarning("No Key", "Please enter the decryption passphrase."))
            return
        if confirm_str and key_str != confirm_str:
            self.progress_bar.after(0, lambda: messagebox.showerror("Passphrase Mismatch", "The passphrase and its confirmation do not match."))
            return
        total_files = len(self.selected_files)
        file_counter = 0
        for file in self.selected_files:
            file = canonicalize_path(file)
            temp_path = None
            try:
                with tempfile.NamedTemporaryFile(dir=os.path.dirname(file), delete=False) as temp_file:
                    temp_path = temp_file.name
                    os.chmod(temp_path, 0o600)
                    with open(file, "rb") as in_file:
                        header_lines = []
                        while True:
                            line = in_file.readline()
                            if not line:
                                raise ValueError("File header missing or corrupted.")
                            if line.strip() == b"":
                                break
                            header_lines.append(line.rstrip(b"\n"))
                        if not header_lines:
                            raise ValueError("No header found.")
                        required_fields = [b"NONCE", b"MODE", b"KEYSALT"]
                        header_dict = validate_header_fields(header_lines, required_fields)
                        mode = header_dict[b"MODE"]
                        key_salt = bytes.fromhex(header_dict[b"KEYSALT"].decode())
                        key, _ = self._derive_key(key_str, key_salt)
                        aesgcm = AESGCM(bytes(key))
                        if mode == b"SINGLE":
                            header_data = b"\n".join(header_lines)
                            if b"NONCE" not in header_dict:
                                raise ValueError("Missing NONCE in header.")
                            nonce = bytes.fromhex(header_dict[b"NONCE"].decode())
                            ciphertext = in_file.read()
                            plaintext = aesgcm.decrypt(nonce, ciphertext, header_data)
                            new_file = file[:-4] if file.endswith(".enc") else file + ".dec"
                            temp_file.write(plaintext)
                            self.progress_bar.after(0, lambda: self.progress_bar.config(value=100))
                        elif mode == b"CHUNKED":
                            required_chunk_fields = [b"NONCE_PREFIX", b"HKDF_SALT", b"HKDF_INFO", b"CHAIN"]
                            header_dict = validate_header_fields(header_lines, required_chunk_fields)
                            nonce_prefix = bytes.fromhex(header_dict[b"NONCE_PREFIX"].decode())
                            hkdf_salt = bytes.fromhex(header_dict[b"HKDF_SALT"].decode())
                            hkdf_info = bytes.fromhex(header_dict[b"HKDF_INFO"].decode())
                            expected_chain = bytes.fromhex(header_dict[b"CHAIN"].decode())
                            hkdf = HKDF(
                                algorithm=hashes.SHA256(),
                                length=32,
                                salt=hkdf_salt,
                                info=hkdf_info
                            )
                            hmac_key = hkdf.derive(bytes(key))
                            per_chunk_mac_key = hmac.new(hmac_key, b"CHUNK_MAC", hashlib.sha256).digest()
                            global_hmac = hmac.new(hmac_key, digestmod=hashlib.sha256)
                            header_data = b"\n".join(header_lines) + b"\n"
                            global_hmac.update(header_data)
                            header_hash = hashlib.sha256(header_data).digest()
                            seq = 0
                            # For progress, use file size if available.
                            file_size = os.path.getsize(file)
                            bytes_read = 0
                            while True:
                                line = in_file.readline()
                                if not line:
                                    raise ValueError("Unexpected end of file; missing HMAC line.")
                                line = line.rstrip(b"\n")
                                if line.startswith(b"HMAC:"):
                                    stored_hmac = line[len(b"HMAC:"):]
                                    break
                                global_hmac.update(line + b"\n")
                                try:
                                    parts = line.split(b" ", 4)
                                    if len(parts) != 5:
                                        raise ValueError("Invalid chunk format.")
                                    seq_part, chain_part, length_part, token_part, mac_part = parts
                                    if not (seq_part.startswith(b"SEQ:") and chain_part.startswith(b"CHAIN:") and length_part.startswith(b"LENGTH:") and token_part.startswith(b"TOKEN:") and mac_part.startswith(b"CHUNKMAC:")):
                                        raise ValueError("Malformed chunk line.")
                                    seq_num = int(seq_part[len(b"SEQ:"):].decode())
                                    if seq_num != seq:
                                        raise ValueError("Sequence number mismatch.")
                                    chain_value = bytes.fromhex(chain_part[len(b"CHAIN:"):].decode())
                                    if chain_value != expected_chain:
                                        raise ValueError("Chaining value mismatch; file may have been tampered with.")
                                    chunk_length = int.from_bytes(length_part[len(b"LENGTH:"):], byteorder='big')
                                    token = token_part[len(b"TOKEN:"):]
                                    stored_chunk_mac = mac_part[len(b"CHUNKMAC:"):]
                                    computed_chunk_mac = hmac.new(per_chunk_mac_key, token, hashlib.sha256).hexdigest().encode()
                                    if computed_chunk_mac != stored_chunk_mac:
                                        raise ValueError(f"Per-chunk MAC verification failed for chunk {seq}.")
                                except Exception as ex:
                                    raise ValueError("Error parsing chunk line: " + str(ex))
                                seq_bytes = f"{seq:08d}".encode("utf-8")
                                nonce = nonce_prefix + seq.to_bytes(4, byteorder='big')
                                chunk_length_bytes = chunk_length.to_bytes(4, byteorder='big')
                                aad = header_hash + b"SEQ:" + seq_bytes + b"LENGTH:" + chunk_length_bytes
                                plaintext_chunk = aesgcm.decrypt(nonce, token, aad)
                                if len(plaintext_chunk) != chunk_length:
                                    raise ValueError("Decrypted chunk length does not match expected length.")
                                temp_file.write(plaintext_chunk)
                                expected_chain = update_chain(expected_chain, token, seq_bytes)
                                seq += 1
                                # Update bytes_read (approximate; assume each chunk contributes its length)
                                bytes_read += chunk_length
                                progress = int((bytes_read / file_size) * 100)
                                self.progress_bar.after(0, lambda p=progress: self.progress_bar.config(value=p))
                            computed_hmac = global_hmac.hexdigest().encode()
                            if computed_hmac != stored_hmac:
                                raise ValueError("Global integrity check failed. File may have been tampered with.")
                            new_file = file[:-4] if file.endswith(".enc") else file + ".dec"
                            self.progress_bar.after(0, lambda: self.progress_bar.config(value=100))
                        else:
                            raise ValueError("Unrecognized encryption mode in header.")
                os.replace(temp_path, new_file)
                self.progress_bar.after(0, lambda: messagebox.showinfo("Success", f"Decrypted: {os.path.basename(new_file)}"))
                if self.delete_var.get():
                    self.secure_delete(file)
            except Exception as e:
                logging.error("Decryption failed for %s: %s", file, str(e))
                self.progress_bar.after(0, lambda: messagebox.showerror("Error", f"Decryption failed for {os.path.basename(file)}. {str(e)}"))
            finally:
                if temp_path and os.path.exists(temp_path):
                    try:
                        os.remove(temp_path)
                    except Exception:
                        logging.warning("Failed to remove temporary file: %s", temp_path)
            file_counter += 1
            overall_progress = int((file_counter / total_files) * 100)
            self.progress_bar.after(0, lambda p=overall_progress: self.progress_bar.config(value=p))
        zeroize_bytearray(key)
        self.key_entry.after(0, lambda: self.key_entry.delete(0, tk.END))
        self.confirm_entry.after(0, lambda: self.confirm_entry.delete(0, tk.END))

if __name__ == "__main__":
    app = FileEncryptorApp()
    app.mainloop()
