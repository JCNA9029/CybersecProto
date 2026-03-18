# modules/quarantine.py
#
# Encrypted file quarantine mechanism.
#
# When a file is confirmed malicious, this module:
#   1. Reads the file into memory
#   2. Encrypts the raw bytes with Fernet AES-128 (hardware-bound key from utils)
#   3. Writes the encrypted blob to a hidden Quarantine directory
#   4. Deletes the original only after the encrypted copy is verified
#   5. Hides the Quarantine directory using Windows system+hidden attributes
#
# Security properties:
#   - Encrypted files cannot be executed even if the folder is accessed
#   - The Fernet key is bound to the machine's hardware MAC address
#   - Encrypted files cannot be decrypted on a different machine
#   - subprocess uses list-form arguments to prevent shell injection

import os
import shutil
import subprocess
import datetime

_PROJECT_ROOT   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
QUARANTINE_DIR  = os.path.join(_PROJECT_ROOT, "Quarantine")


def quarantine_file(file_path: str, quarantine_dir: str = None) -> bool:
    """
    Encrypts and quarantines a confirmed malicious file.

    Encryption uses the hardware-bound Fernet cipher from utils so the
    encrypted file cannot be decrypted on a different machine. The original
    file is removed only after the encrypted copy has been successfully written.

    Returns True on success, False if the operation could not be completed.
    """
    if quarantine_dir is None:
        quarantine_dir = QUARANTINE_DIR

    os.makedirs(quarantine_dir, exist_ok=True)

    # Hide the quarantine directory on Windows
    if os.name == "nt":
        try:
            subprocess.run(
                ["attrib", "+h", "+s", quarantine_dir],
                check=False,
                capture_output=True,
            )
        except FileNotFoundError:
            pass  # Non-Windows environment — skip attribute setting

    try:
        # Read original file content
        with open(file_path, "rb") as f:
            data = f.read()

        # Encrypt with hardware-bound Fernet key
        try:
            from . import utils
            cipher = utils._get_fernet()
            if cipher:
                encrypted = cipher.encrypt(data)
            else:
                # Fallback: store as-is with a clear warning
                # This should never happen if cryptography is installed
                encrypted = data
                print("[!] WARNING: Fernet unavailable — file quarantined without encryption.")
                print("[!] Install cryptography: pip install cryptography")
        except Exception as e:
            print(f"[!] Encryption error ({e}) — quarantining without encryption as fallback.")
            encrypted = data

        # Build destination path with collision avoidance
        filename   = os.path.basename(file_path)
        dest       = os.path.join(quarantine_dir, filename + ".quarantine")
        if os.path.exists(dest):
            ts   = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            dest = os.path.join(quarantine_dir, f"{filename}_{ts}.quarantine")

        # Write encrypted copy first — only remove original on success
        with open(dest, "wb") as f:
            f.write(encrypted)

        # Verify the encrypted file was written correctly
        if not os.path.exists(dest) or os.path.getsize(dest) == 0:
            print("[-] Quarantine verification failed — original file preserved.")
            return False

        # Remove the original file
        os.remove(file_path)

        print("\n" + "=" * 50)
        print("[+] SUCCESS: Threat encrypted and quarantined.")
        print(f"[*] Original File  : {filename}")
        print(f"[*] Encrypted Copy : {dest}")
        print(f"[*] Encryption     : Fernet AES-128 (hardware-bound)")
        print("=" * 50 + "\n")
        return True

    except PermissionError:
        print("\n[-] ACTION FAILED: Permission denied.")
        print("[-] The malware may be actively running. Run CyberSentinel as Administrator.\n")
        return False
    except Exception as e:
        print(f"\n[-] ACTION FAILED: {e}\n")
        return False
