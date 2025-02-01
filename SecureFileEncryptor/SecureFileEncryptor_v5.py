#!/usr/bin/env python3
"""
SecureFileEncryptor_v5.py
Version: v5.0.0

A GUI tool for encrypting and decrypting files, folders, or multiple files.
When more than one item is selected (or if a folder is selected), the items are
first archived into a ZIP file (thus preserving directory structure) and then
encrypted into a single file.

Encryption uses AES-GCM with either single-shot (for small files) or chunked
modes (for large files). In chunked mode, each chunk’s associated data (AAD) is
enhanced with a digest of the header and a sequence number to bind the header to
the encrypted data.

On decryption, if the header indicates an archive (ARCHIVE:ZIP), the user is prompted
to extract the decrypted ZIP archive.

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
import zipfile
import shutil

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Program metadata
PROGRAM_NAME = "SecureFileEncryptor"
VERSION = "v5.0.0"

# Constants for encryption processing
CHUNK_THRESHOLD = 10 * 1024 * 1024  # 10 MB threshold
CHUNK_SIZE = 1024 * 1024            # 1 MB per chunk
PBKDF2_ITERATIONS = 200_000         # Increased iterations for PBKDF2

# Configure logging: log errors to file with owner-read/write only.
logging.basicConfig(
    filename="file_encryptor_v5.log",
    level=logging.ERROR,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
try:
    os.chmod("file_encryptor_v5.log", 0o600)
except Exception as e:
    logging.warning("Could not set log file permissions: " + str(e))

def update_chain(chaining_value: bytes, token: bytes, seq_bytes: bytes) -> bytes:
    """
    Update chaining value: new_value = SHA256(chaining_value || token || seq_bytes).
    This binds the order and integrity of each chunk.
    """
    return hashlib.sha256(chaining_value + token + seq_bytes).digest()

class FileEncryptorApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{PROGRAM_NAME} {VERSION}")
        window_width = 600
        window_height = int(window_width / 1.618)
        self.geometry(f"{window_width}x{window_height}")
        # List of selected file/folder paths
        self.selected_items = []
        self.create_widgets()

    def create_widgets(self):
        # Selection frame with buttons for files and folders.
        selection_frame = tk.Frame(self)
        selection_frame.pack(pady=10)

        files_button = tk.Button(selection_frame, text="Select Files", command=self.select_files)
        files_button.grid(row=0, column=0, padx=5)

        folder_button = tk.Button(selection_frame, text="Select Folder", command=self.select_folder)
        folder_button.grid(row=0, column=1, padx=5)

        clear_button = tk.Button(selection_frame, text="Clear Selection", command=self.clear_selection)
        clear_button.grid(row=0, column=2, padx=5)

        # Listbox to show selected items.
        self.listbox = tk.Listbox(self, width=80, height=8)
        self.listbox.pack(pady=5)

        # Key entry and generation.
        key_frame = tk.Frame(self)
        key_frame.pack(pady=10)
        key_label = tk.Label(key_frame, text="Key:")
        key_label.pack(side=tk.LEFT)
        self.key_entry = tk.Entry(key_frame, width=50, show="*")
        self.key_entry.pack(side=tk.LEFT, padx=5)
        generate_button = tk.Button(key_frame, text="Generate Key", command=self.generate_key)
        generate_button.pack(side=tk.LEFT)

        # Checkbox for secure deletion.
        self.delete_var = tk.BooleanVar()
        self.delete_checkbox = tk.Checkbutton(
            self, text="Securely delete original items", variable=self.delete_var
        )
        self.delete_checkbox.pack(pady=5)

        # Action buttons.
        action_frame = tk.Frame(self)
        action_frame.pack(pady=20)
        encrypt_button = tk.Button(action_frame, text="Encrypt Selected", command=self.encrypt_items)
        encrypt_button.pack(side=tk.LEFT, padx=10)
        decrypt_button = tk.Button(action_frame, text="Decrypt File", command=self.decrypt_file)
        decrypt_button.pack(side=tk.LEFT, padx=10)

    def select_files(self):
        """Allow user to select one or more files."""
        paths = filedialog.askopenfilenames(title="Select Files")
        if paths:
            for p in paths:
                if p not in self.selected_items:
                    self.selected_items.append(p)
                    self.listbox.insert(tk.END, p)

    def select_folder(self):
        """Allow user to select a folder."""
        path = filedialog.askdirectory(title="Select Folder")
        if path and path not in self.selected_items:
            self.selected_items.append(path)
            self.listbox.insert(tk.END, path)

    def clear_selection(self):
        """Clear all selected items."""
        self.selected_items = []
        self.listbox.delete(0, tk.END)

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

    def secure_delete(self, path, passes=3):
        """
        Overwrite the file with random data a number of times before deletion.
        Flush and (when possible) sync changes to disk before removal.
        Note: This is best-effort and may not guarantee deletion on all storage.
        """
        try:
            if os.path.exists(path):
                length = os.path.getsize(path)
                with open(path, "r+b", buffering=0) as f:
                    for _ in range(passes):
                        f.seek(0)
                        for offset in range(0, length, 4096):
                            block_size = min(4096, length - offset)
                            f.write(os.urandom(block_size))
                        f.flush()
                        os.fsync(f.fileno())
                os.remove(path)
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

    def create_zip_archive(self, items: list) -> str:
        """
        Create a ZIP archive containing the selected items (files and/or folders).
        Returns the path to the created archive.
        """
        temp_zip = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
        temp_zip.close()  # We'll write to it using zipfile module.
        with zipfile.ZipFile(temp_zip.name, "w", compression=zipfile.ZIP_DEFLATED) as zipf:
            used_names = {}
            for item in items:
                if os.path.isfile(item):
                    arcname = os.path.basename(item)
                    # Handle duplicate names.
                    if arcname in used_names:
                        used_names[arcname] += 1
                        name, ext = os.path.splitext(arcname)
                        arcname = f"{name}_{used_names[arcname]}{ext}"
                    else:
                        used_names[arcname] = 1
                    zipf.write(item, arcname=arcname)
                elif os.path.isdir(item):
                    base_dir = os.path.basename(os.path.normpath(item))
                    for root, dirs, files in os.walk(item):
                        for file in files:
                            full_path = os.path.join(root, file)
                            rel_path = os.path.relpath(full_path, os.path.dirname(item))
                            # Prepend the folder's base name.
                            arcname = os.path.join(base_dir, rel_path)
                            zipf.write(full_path, arcname=arcname)
        return temp_zip.name

    def encrypt_items(self):
        """Encrypt the selected item(s) into a single encrypted file."""
        if not self.selected_items:
            messagebox.showwarning("No Items Selected", "Please select file(s) and/or folder(s) to encrypt.")
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

        # Determine input file to encrypt.
        archive_mode = False
        if len(self.selected_items) == 1 and os.path.isfile(self.selected_items[0]):
            input_path = self.selected_items[0]
        else:
            # Multiple items or a folder selected: create a ZIP archive.
            try:
                input_path = self.create_zip_archive(self.selected_items)
                archive_mode = True
            except Exception as e:
                logging.exception("Failed to create ZIP archive")
                messagebox.showerror("Error", "Failed to create ZIP archive from selected items.")
                return

        try:
            file_size = os.path.getsize(input_path)
        except Exception as e:
            logging.exception("Failed to get file size")
            messagebox.showerror("Error", "Failed to access the input file size.")
            return

        # Ask user for output filename.
        new_file = filedialog.asksaveasfilename(
            title="Save Encrypted File As", defaultextension=".enc",
            filetypes=[("Encrypted Files", "*.enc"), ("All Files", "*.*")]
        )
        if not new_file:
            return
        if not self.confirm_overwrite(new_file):
            return

        try:
            temp_fd, temp_path = tempfile.mkstemp(dir=os.path.dirname(new_file))
            os.close(temp_fd)
            os.chmod(temp_path, 0o600)

            with open(temp_path, "wb") as out_file:
                header_lines = [f"{PROGRAM_NAME} {VERSION}".encode()]
                # Mark mode: for single file mode, we use MODE:SINGLE; for archive mode, add ARCHIVE:ZIP.
                if not archive_mode:
                    header_lines.append(b"MODE:SINGLE")
                else:
                    header_lines.append(b"MODE:ARCHIVE")
                    header_lines.append(b"ARCHIVE:ZIP")
                if is_passphrase:
                    header_lines.append(b"KEYSALT:" + key_salt.hex().encode())
                # Encryption parameters (nonce or nonce prefix etc.) will be added below.
                if file_size < CHUNK_THRESHOLD:
                    # Single-shot encryption mode.
                    nonce = os.urandom(12)
                    header_lines.append(b"NONCE:" + nonce.hex().encode())
                    header_data = b"\n".join(header_lines)
                    with open(input_path, "rb") as in_file:
                        plaintext = in_file.read()
                    ciphertext = aesgcm.encrypt(nonce, plaintext, header_data)
                    out_file.write(header_data + b"\n\n" + ciphertext)
                else:
                    # Chunked mode.
                    nonce_prefix = os.urandom(8)  # 8-byte prefix; nonce = prefix + 4-byte counter.
                    hkdf_salt = os.urandom(16)
                    hkdf_info = os.urandom(16)
                    initial_chain = os.urandom(32)
                    header_lines.append(b"NONCE_PREFIX:" + nonce_prefix.hex().encode())
                    header_lines.append(b"HKDF_SALT:" + hkdf_salt.hex().encode())
                    header_lines.append(b"HKDF_INFO:" + hkdf_info.hex().encode())
                    header_lines.append(b"CHAIN:" + initial_chain.hex().encode())
                    header_data = b"\n".join(header_lines) + b"\n"
                    out_file.write(header_data)

                    # Derive a global HMAC key.
                    hkdf = HKDF(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=hkdf_salt,
                        info=hkdf_info
                    )
                    hmac_key = hkdf.derive(key)
                    global_hmac = hmac.new(hmac_key, digestmod=hashlib.sha256)
                    global_hmac.update(header_data)

                    # Compute a header digest to bind in each chunk’s AAD.
                    header_hash = hashlib.sha256(header_data).digest()

                    seq = 0
                    chaining_value = initial_chain
                    with open(input_path, "rb") as in_file:
                        while True:
                            chunk = in_file.read(CHUNK_SIZE)
                            if not chunk:
                                break
                            seq_bytes = f"{seq:08d}".encode("utf-8")
                            nonce = nonce_prefix + seq.to_bytes(4, byteorder='big')
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
            messagebox.showinfo("Success", f"Items encrypted successfully:\n{new_file}")

            # Optionally securely delete the originals.
            if self.delete_var.get():
                for path in self.selected_items:
                    self.secure_delete(path)
                # If an archive was created temporarily, remove it.
                if archive_mode and os.path.exists(input_path):
                    os.remove(input_path)
        except Exception as e:
            logging.exception("Encryption failed")
            messagebox.showerror("Error", "Encryption failed. Please check the log for details.")
        finally:
            # Overwrite key material.
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
        """
        Decrypt an encrypted file produced by SecureFileEncryptor_v5.py.
        If the header indicates an archive (ARCHIVE:ZIP), the user will be
        prompted to extract its contents.
        """
        encrypted_path = filedialog.askopenfilename(title="Select Encrypted File", filetypes=[("Encrypted Files", "*.enc"), ("All Files", "*.*")])
        if not encrypted_path:
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
            temp_fd, temp_path = tempfile.mkstemp(dir=os.path.dirname(encrypted_path))
            os.close(temp_fd)
            os.chmod(temp_path, 0o600)

            with open(encrypted_path, "rb") as in_file:
                header_lines = []
                # Read header lines until an empty line (for single-shot) or until header termination.
                while True:
                    line = in_file.readline()
                    if not line:
                        raise ValueError("File header missing or corrupted.")
                    if line.strip() == b"":
                        break
                    header_lines.append(line.rstrip(b"\n"))
                if not header_lines:
                    raise ValueError("No header found.")
                header_data = b"\n".join(header_lines)
                mode_line = header_lines[1] if len(header_lines) > 1 else b""
                archive_flag = False
                if mode_line == b"MODE:SINGLE":
                    # Single-shot file mode.
                    nonce = None
                    for item in header_lines:
                        if item.startswith(b"NONCE:"):
                            nonce = bytes.fromhex(item[6:].decode())
                    if nonce is None:
                        raise ValueError("Missing NONCE in header.")
                    # Re-derive key if KEYSALT is present.
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
                    output_path = encrypted_path[:-4] if encrypted_path.endswith(".enc") else encrypted_path + ".dec"
                    with open(temp_path, "wb") as out_file:
                        out_file.write(plaintext)
                elif mode_line in (b"MODE:ARCHIVE", b"MODE:CHUNKED"):
                    # If header includes "ARCHIVE:ZIP", then this is an archived set.
                    for item in header_lines:
                        if item.startswith(b"ARCHIVE:ZIP"):
                            archive_flag = True
                            break

                    # Chunked mode decryption.
                    # Parse necessary header values.
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

                    hkdf = HKDF(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=hkdf_salt,
                        info=hkdf_info
                    )
                    hmac_key = hkdf.derive(key)
                    global_hmac = hmac.new(hmac_key, digestmod=hashlib.sha256)
                    header_data_full = header_data + b"\n"
                    global_hmac.update(header_data_full)
                    header_hash = hashlib.sha256(header_data_full).digest()

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
                            aad = header_hash + b"SEQ:" + seq_bytes
                            plaintext_chunk = aesgcm.decrypt(nonce, token, aad)
                            out_file.write(plaintext_chunk)
                            expected_chain = update_chain(expected_chain, token, seq_bytes)
                            seq += 1

                    computed_hmac = global_hmac.hexdigest().encode()
                    if computed_hmac != stored_hmac:
                        raise ValueError("Global integrity check failed. File may have been tampered with.")
                    output_path = encrypted_path[:-4] if encrypted_path.endswith(".enc") else encrypted_path + ".dec"
                else:
                    raise ValueError("Unrecognized encryption mode in header.")
            os.replace(temp_path, output_path)
            messagebox.showinfo("Success", f"File decrypted successfully:\n{output_path}")

            # If the decrypted file is an archive, prompt the user to extract it.
            if archive_flag:
                if messagebox.askyesno("Extract Archive", "The decrypted file is a ZIP archive. Extract its contents?"):
                    extract_dir = filedialog.askdirectory(title="Select Extraction Folder")
                    if extract_dir:
                        try:
                            with zipfile.ZipFile(output_path, "r") as zip_ref:
                                zip_ref.extractall(extract_dir)
                            messagebox.showinfo("Extraction Complete", f"Archive extracted to:\n{extract_dir}")
                        except Exception as ex:
                            logging.exception("Extraction failed")
                            messagebox.showerror("Error", "Failed to extract archive. Please check the log for details.")
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
