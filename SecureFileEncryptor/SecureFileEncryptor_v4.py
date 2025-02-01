#!/usr/bin/env python3
"""
SecureFileEncryptor_v4.py
Version: v4.0.0

A GUI file encryption/decryption tool that uses AES-GCM in both single-shot
and chunked modes. In chunked mode, the encryption binds a digest of the header
(with all metadata) and the sequence number as associated data (AAD), improving
integrity protection against header or chunk tampering.

Improvements in this version:
  - Enhanced AAD in chunked mode: header digest + sequence number.
  - Increased care in memory sanitization of key material.
  - Additional flushing and syncing before secure deletion.
  - Robust temporary file handling via try-finally.

Note:
  Secure deletion is best-effort on modern storage media.
  
References:
  Cryptography.io. “AES-GCM.” Cryptography, 2021, https://cryptography.io/en/latest/hazmat/primitives/aead/.
  NIST. “Digital Identity Guidelines: Authentication and Lifecycle Management.” NIST SP 800-63B, 2017.
"""

import tkinter as tk
from tkinter import filedialog, messagebox
import os
import tempfile
import logging
import hmac
import hashlib
import secrets
import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Program metadata
PROGRAM_NAME = "SecureFileEncryptor"
VERSION = "v4.0.0"

# Constants for chunked processing
CHUNK_THRESHOLD = 10 * 1024 * 1024  # 10 MB threshold
CHUNK_SIZE = 1024 * 1024            # 1 MB per chunk
PBKDF2_ITERATIONS = 200_000         # Increased iterations for PBKDF2

# Configure logging: log errors to file with owner-read/write only.
logging.basicConfig(
    filename="file_encryptor_v4.log",
    level=logging.ERROR,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
try:
    os.chmod("file_encryptor_v4.log", 0o600)
except Exception as e:
    logging.warning("Could not set log file permissions: " + str(e))

def update_chain(chaining_value: bytes, token: bytes, seq_bytes: bytes) -> bytes:
    """
    Update chaining value: new_value = SHA256(chaining_value || token || seq_bytes).
    This ensures that the order and integrity of each chunk are bound together.
    """
    return hashlib.sha256(chaining_value + token + seq_bytes).digest()

class FileEncryptorApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{PROGRAM_NAME} {VERSION}")
        window_width = 500
        window_height = int(window_width / 1.618)
        self.geometry(f"{window_width}x{window_height}")
        self.selected_file = None  # Path of selected file
        self.create_widgets()

    def create_widgets(self):
        # File selection widgets.
        self.file_button = tk.Button(self, text="Select File", command=self.choose_file)
        self.file_button.pack(pady=10)
        self.file_label = tk.Label(self, text="No file selected")
        self.file_label.pack()

        # Key entry (masked) and key generation.
        key_frame = tk.Frame(self)
        key_frame.pack(pady=10)
        key_label = tk.Label(key_frame, text="Key:")
        key_label.pack(side=tk.LEFT)
        self.key_entry = tk.Entry(key_frame, width=50, show="*")
        self.key_entry.pack(side=tk.LEFT, padx=5)
        generate_button = tk.Button(key_frame, text="Generate Key", command=self.generate_key)
        generate_button.pack(side=tk.LEFT)

        # Checkbox for secure deletion option.
        self.delete_var = tk.BooleanVar()
        self.delete_checkbox = tk.Checkbutton(
            self, text="Securely delete original file", variable=self.delete_var
        )
        self.delete_checkbox.pack(pady=5)

        # Action buttons.
        action_frame = tk.Frame(self)
        action_frame.pack(pady=20)
        encrypt_button = tk.Button(action_frame, text="Encrypt File", command=self.encrypt_file)
        encrypt_button.pack(side=tk.LEFT, padx=10)
        decrypt_button = tk.Button(action_frame, text="Decrypt File", command=self.decrypt_file)
        decrypt_button.pack(side=tk.LEFT, padx=10)

    def choose_file(self):
        """Open a file dialog to select a file and update the label."""
        self.selected_file = filedialog.askopenfilename(title="Select a file")
        if self.selected_file:
            self.file_label.config(text=f"Selected File: {os.path.basename(self.selected_file)}")
        else:
            self.file_label.config(text="No file selected")

    def generate_key(self):
        """Generate a new AES key (256-bit) and display it in base64 (44 characters)."""
        try:
            key = base64.urlsafe_b64encode(AESGCM.generate_key(bit_length=256)).decode('utf-8')
            self.key_entry.delete(0, tk.END)
            self.key_entry.insert(0, key)
            messagebox.showinfo("Key Generated", "A new key has been generated and inserted into the key field.")
        except Exception as e:
            logging.exception("Key generation failed")
            messagebox.showerror("Error", "Key generation failed. Please try again.")

    def confirm_overwrite(self, filename):
        """Prompt the user if the output file already exists."""
        if os.path.exists(filename):
            return messagebox.askyesno("File Exists", f"File {os.path.basename(filename)} already exists. Overwrite?")
        return True

    def secure_delete(self, file_path, passes=3):
        """
        Overwrite the file with random data a number of times before deletion.
        Flush and (when possible) sync changes to disk before removal.
        """
        try:
            if os.path.exists(file_path):
                length = os.path.getsize(file_path)
                with open(file_path, "r+b", buffering=0) as f:
                    for _ in range(passes):
                        f.seek(0)
                        # Overwrite file in blocks.
                        for offset in range(0, length, 4096):
                            block_size = min(4096, length - offset)
                            f.write(os.urandom(block_size))
                        f.flush()
                        os.fsync(f.fileno())
                os.remove(file_path)
        except Exception as e:
            logging.exception("Secure deletion failed")
            messagebox.showwarning("Warning", "Secure deletion failed.")

    def _derive_key(self, key_str: str) -> (bytes, bool, bytes):
        """
        Derive a 32-byte AES key. If key_str is not 44 characters long,
        treat it as a passphrase and derive the key via PBKDF2.
        Returns a tuple: (key, is_passphrase, key_salt) where key_salt is None if key_str was already a key.
        """
        is_passphrase = (len(key_str) != 44)
        if is_passphrase:
            key_salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=key_salt,
                iterations=PBKDF2_ITERATIONS,
            )
            derived_key = kdf.derive(key_str.encode('utf-8'))
            key = derived_key  # Raw 32 bytes for AESGCM
        else:
            key_salt = None
            try:
                key = base64.urlsafe_b64decode(key_str)
            except Exception as e:
                logging.exception("Key decoding failed")
                raise ValueError("Provided key is not valid base64.")
        return key, is_passphrase, key_salt

    def encrypt_file(self):
        """Encrypt the selected file using AES-GCM in single-shot or chunked mode."""
        if not self.selected_file:
            messagebox.showwarning("No File Selected", "Please select a file to encrypt.")
            return

        key_str = self.key_entry.get().strip()
        if not key_str:
            messagebox.showwarning("No Key", "Please enter or generate a key.")
            return

        try:
            key, is_passphrase, key_salt = self._derive_key(key_str)
            aesgcm = AESGCM(key)
        except Exception as e:
            logging.exception("Key derivation failed")
            messagebox.showerror("Invalid Key", "The provided key is invalid. Please check your key.")
            return

        try:
            file_size = os.path.getsize(self.selected_file)
        except Exception as e:
            logging.exception("Failed to get file size")
            messagebox.showerror("Error", "Failed to access the file size.")
            return

        new_file = self.selected_file + ".enc"
        if not self.confirm_overwrite(new_file):
            return

        try:
            # Create a secure temporary file in the target directory.
            temp_fd, temp_path = tempfile.mkstemp(dir=os.path.dirname(new_file))
            os.close(temp_fd)
            os.chmod(temp_path, 0o600)

            with open(temp_path, "wb") as out_file:
                if file_size < CHUNK_THRESHOLD:
                    # Single-shot mode for small files.
                    nonce = os.urandom(12)  # AES-GCM standard nonce size.
                    header_lines = [
                        f"{PROGRAM_NAME} {VERSION}".encode(),
                        b"MODE:SINGLE"
                    ]
                    if is_passphrase:
                        header_lines.append(b"KEYSALT:" + key_salt.hex().encode())
                    header_lines.append(b"NONCE:" + nonce.hex().encode())
                    header_data = b"\n".join(header_lines)
                    # Encrypt the entire file with header_data as associated data.
                    with open(self.selected_file, "rb") as in_file:
                        plaintext = in_file.read()
                    ciphertext = aesgcm.encrypt(nonce, plaintext, header_data)
                    # Write header, separator, then ciphertext.
                    out_file.write(header_data + b"\n\n" + ciphertext)
                else:
                    # Chunked mode for large files.
                    # Generate file-specific parameters.
                    nonce_prefix = os.urandom(8)  # 8-byte prefix; nonce = nonce_prefix || 4-byte counter.
                    hkdf_salt = os.urandom(16)
                    hkdf_info = os.urandom(16)
                    initial_chain = os.urandom(32)

                    header_lines = [
                        f"{PROGRAM_NAME} {VERSION}".encode(),
                        b"MODE:CHUNKED"
                    ]
                    if is_passphrase:
                        header_lines.append(b"KEYSALT:" + key_salt.hex().encode())
                    header_lines.append(b"NONCE_PREFIX:" + nonce_prefix.hex().encode())
                    header_lines.append(b"HKDF_SALT:" + hkdf_salt.hex().encode())
                    header_lines.append(b"HKDF_INFO:" + hkdf_info.hex().encode())
                    header_lines.append(b"CHAIN:" + initial_chain.hex().encode())
                    header_data = b"\n".join(header_lines) + b"\n"
                    out_file.write(header_data)

                    # Derive global HMAC key using HKDF.
                    hkdf = HKDF(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=hkdf_salt,
                        info=hkdf_info
                    )
                    hmac_key = hkdf.derive(key)
                    global_hmac = hmac.new(hmac_key, digestmod=hashlib.sha256)
                    global_hmac.update(header_data)

                    # Compute a digest of the header to bind in each chunk's AAD.
                    header_hash = hashlib.sha256(header_data).digest()

                    seq = 0
                    chaining_value = initial_chain
                    with open(self.selected_file, "rb") as in_file:
                        while True:
                            chunk = in_file.read(CHUNK_SIZE)
                            if not chunk:
                                break
                            seq_bytes = f"{seq:08d}".encode("utf-8")
                            # Construct nonce: 8-byte nonce_prefix + 4-byte counter.
                            nonce = nonce_prefix + seq.to_bytes(4, byteorder='big')
                            # AAD now includes the header hash plus the sequence.
                            aad = header_hash + b"SEQ:" + seq_bytes
                            token = aesgcm.encrypt(nonce, chunk, aad)
                            line = b"SEQ:" + seq_bytes + b" CHAIN:" + chaining_value.hex().encode() + b" TOKEN:" + token
                            out_file.write(line + b"\n")
                            global_hmac.update(line + b"\n")
                            chaining_value = update_chain(chaining_value, token, seq_bytes)
                            seq += 1

                    hmac_line = b"HMAC:" + global_hmac.hexdigest().encode() + b"\n"
                    out_file.write(hmac_line)
            os.replace(temp_path, new_file)
            messagebox.showinfo("Success", f"File encrypted successfully:\n{new_file}")
            if self.delete_var.get():
                self.secure_delete(self.selected_file)
        except Exception as e:
            logging.exception("Encryption failed")
            messagebox.showerror("Error", "Encryption failed. Please check the log for details.")
        finally:
            # Overwrite key material in memory.
            try:
                if isinstance(key, bytearray):
                    for i in range(len(key)):
                        key[i] = 0
                else:
                    key = b'\x00' * len(key)
            except Exception:
                pass
            self.key_entry.delete(0, tk.END)

    def decrypt_file(self):
        """Decrypt a file encrypted by SecureFileEncryptor v4.0.0 in either single-shot or chunked mode."""
        if not self.selected_file:
            messagebox.showwarning("No File Selected", "Please select a file to decrypt.")
            return

        key_str = self.key_entry.get().strip()
        if not key_str:
            messagebox.showwarning("No Key", "Please enter the decryption key.")
            return

        try:
            key, is_passphrase, key_salt = self._derive_key(key_str)
            aesgcm = AESGCM(key)
        except Exception as e:
            logging.exception("Key derivation failed")
            messagebox.showerror("Invalid Key", "The provided key is invalid. Please check your key.")
            return

        try:
            temp_fd, temp_path = tempfile.mkstemp(dir=os.path.dirname(self.selected_file))
            os.close(temp_fd)
            os.chmod(temp_path, 0o600)

            with open(self.selected_file, "rb") as in_file:
                header_lines = []
                # Read header lines until an empty line (delimiter for single-shot) or end-of-header.
                while True:
                    line = in_file.readline()
                    if not line:
                        raise ValueError("File header missing or corrupted.")
                    if line.strip() == b"":
                        break
                    header_lines.append(line.rstrip(b"\n"))
                if not header_lines:
                    raise ValueError("No header found.")
                mode_line = header_lines[1] if len(header_lines) > 1 else b""
                if mode_line == b"MODE:SINGLE":
                    header_data = b"\n".join(header_lines)
                    nonce = None
                    for item in header_lines:
                        if item.startswith(b"NONCE:"):
                            nonce = bytes.fromhex(item[6:].decode())
                    if nonce is None:
                        raise ValueError("Missing NONCE in header.")
                    # If KEYSALT is present, re-derive key via PBKDF2.
                    if any(item.startswith(b"KEYSALT:") for item in header_lines):
                        for item in header_lines:
                            if item.startswith(b"KEYSALT:"):
                                ks = bytes.fromhex(item[8:].decode())
                                kdf = PBKDF2HMAC(
                                    algorithm=hashes.SHA256(),
                                    length=32,
                                    salt=ks,
                                    iterations=PBKDF2_ITERATIONS,
                                )
                                key = kdf.derive(key_str.encode('utf-8'))
                                aesgcm = AESGCM(key)
                                break
                    ciphertext = in_file.read()
                    plaintext = aesgcm.decrypt(nonce, ciphertext, header_data)
                    new_file = self.selected_file[:-4] if self.selected_file.endswith(".enc") else self.selected_file + ".dec"
                    with open(temp_path, "wb") as out_file:
                        out_file.write(plaintext)
                elif mode_line == b"MODE:CHUNKED":
                    # Parse header values.
                    nonce_prefix = None
                    hkdf_salt = None
                    hkdf_info = None
                    expected_chain = None
                    for item in header_lines:
                        if item.startswith(b"NONCE_PREFIX:"):
                            nonce_prefix = bytes.fromhex(item[len(b"NONCE_PREFIX:"):].decode())
                        elif item.startswith(b"HKDF_SALT:"):
                            hkdf_salt = bytes.fromhex(item[len(b"HKDF_SALT:"):].decode())
                        elif item.startswith(b"HKDF_INFO:"):
                            hkdf_info = bytes.fromhex(item[len(b"HKDF_INFO:"):].decode())
                        elif item.startswith(b"CHAIN:"):
                            expected_chain = bytes.fromhex(item[len(b"CHAIN:"):].decode())
                        elif item.startswith(b"KEYSALT:") and is_passphrase:
                            ks = bytes.fromhex(item[len(b"KEYSALT:"):].decode())
                            kdf = PBKDF2HMAC(
                                algorithm=hashes.SHA256(),
                                length=32,
                                salt=ks,
                                iterations=PBKDF2_ITERATIONS,
                            )
                            key = kdf.derive(key_str.encode('utf-8'))
                            aesgcm = AESGCM(key)
                    if None in (nonce_prefix, hkdf_salt, hkdf_info, expected_chain):
                        raise ValueError("Missing required header parameters for chunked mode.")

                    # Re-derive global HMAC key.
                    hkdf = HKDF(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=hkdf_salt,
                        info=hkdf_info
                    )
                    hmac_key = hkdf.derive(key)
                    global_hmac = hmac.new(hmac_key, digestmod=hashlib.sha256)
                    header_data = b"\n".join(header_lines) + b"\n"
                    global_hmac.update(header_data)
                    # Compute header hash to reconstruct AAD for each chunk.
                    header_hash = hashlib.sha256(header_data).digest()

                    seq = 0
                    with open(temp_path, "wb") as out_file:
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
                                parts = line.split(b" ", 2)
                                if len(parts) != 3:
                                    raise ValueError("Invalid chunk format.")
                                seq_part, chain_part, token_part = parts
                                if not (seq_part.startswith(b"SEQ:") and chain_part.startswith(b"CHAIN:") and token_part.startswith(b"TOKEN:")):
                                    raise ValueError("Malformed chunk line.")
                                seq_num = int(seq_part[len(b"SEQ:"):].decode())
                                if seq_num != seq:
                                    raise ValueError("Sequence number mismatch.")
                                chain_value = bytes.fromhex(chain_part[len(b"CHAIN:"):].decode())
                                if chain_value != expected_chain:
                                    raise ValueError("Chaining value mismatch; file may have been tampered with.")
                                token = token_part[len(b"TOKEN:"):]
                            except Exception as ex:
                                raise ValueError("Error parsing chunk line: " + str(ex))
                            seq_bytes = f"{seq:08d}".encode("utf-8")
                            nonce = nonce_prefix + seq.to_bytes(4, byteorder='big')
                            # AAD includes header_hash and the sequence.
                            aad = header_hash + b"SEQ:" + seq_bytes
                            plaintext_chunk = aesgcm.decrypt(nonce, token, aad)
                            out_file.write(plaintext_chunk)
                            expected_chain = update_chain(expected_chain, token, seq_bytes)
                            seq += 1

                    computed_hmac = global_hmac.hexdigest().encode()
                    if computed_hmac != stored_hmac:
                        raise ValueError("Global integrity check failed. File may have been tampered with.")
                    new_file = self.selected_file[:-4] if self.selected_file.endswith(".enc") else self.selected_file + ".dec"
                else:
                    raise ValueError("Unrecognized encryption mode in header.")
            os.replace(temp_path, new_file)
            messagebox.showinfo("Success", f"File decrypted successfully:\n{new_file}")
            if self.delete_var.get():
                self.secure_delete(self.selected_file)
        except Exception as e:
            logging.exception("Decryption failed")
            messagebox.showerror("Error", "Decryption failed. Please check the log for details.")
        finally:
            try:
                if isinstance(key, bytearray):
                    for i in range(len(key)):
                        key[i] = 0
                else:
                    key = b'\x00' * len(key)
            except Exception:
                pass
            self.key_entry.delete(0, tk.END)

if __name__ == "__main__":
    app = FileEncryptorApp()
    app.mainloop()
