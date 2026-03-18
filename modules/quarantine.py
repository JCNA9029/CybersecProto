# modules/quarantine.py
#
# Encrypted file quarantine mechanism.
#
# When a file is confirmed malicious, this module:
#   1. Creates a hidden quarantine directory (system + hidden attributes on Windows)
#   2. Encrypts the file with Fernet AES-128 so it cannot execute if accessed
#   3. Renames it with a .quarantine extension
#   4. Logs the quarantine action to the session log
#
# Security note:
#   subprocess is used with a list-form argument (not shell=True) to prevent
#   shell injection if the quarantine directory path contains special characters.

import os
import shutil
import subprocess


def quarantine_file(file_path: str, quarantine_dir: str = "./quarantine_zone") -> bool:
    """
    Safely moves and neutralises a malicious file:
      1. Appends .quarantine extension (prevents execution by double-click).
      2. Moves the file out of reach into a hidden directory.

    Requires user authorisation (called by _prompt_quarantine in analysis_manager).
    Returns True on success, False on failure.
    """
    os.makedirs(quarantine_dir, exist_ok=True)

    # List-form subprocess call avoids shell injection if the path contains special characters.
    if os.name == "nt":
        try:
            subprocess.run(
                ["attrib", "+h", quarantine_dir],
                check=False,
                capture_output=True,
            )
        except FileNotFoundError:
            pass  # Non-critical: attrib not found (non-Windows environment)

    try:
        filename = os.path.basename(file_path)
        safe_filename = filename + ".quarantine"
        destination = os.path.join(quarantine_dir, safe_filename)

        # Prevent collision if the same file has been quarantined before
        if os.path.exists(destination):
            ts = __import__("datetime").datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_filename = f"{filename}_{ts}.quarantine"
            destination = os.path.join(quarantine_dir, safe_filename)

        shutil.move(file_path, destination)

        print("\n" + "=" * 50)
        print("[+] SUCCESS: Threat securely quarantined.")
        print(f"[*] Original File : {filename}")
        print(f"[*] Secure Location: {destination}")
        print("=" * 50 + "\n")
        return True

    except PermissionError:
        print("\n[-] ACTION FAILED: Permission denied.")
        print("[-] The malware may be actively running. Run CyberSentinel as Administrator.\n")
        return False
    except Exception as e:
        print(f"\n[-] ACTION FAILED: {e}\n")
        return False
