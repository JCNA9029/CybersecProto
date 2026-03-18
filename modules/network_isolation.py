# This module handles network isolation by modifying Windows Firewall rules.
# It provides functions to block all inbound and outbound traffic to contain threats such as C2C , as well as a
# restore function to revert the firewall back to its default state. 
import subprocess
import ctypes
import os

def is_admin():
    """Checks if the Python script has Windows Administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

def isolate_network():
    """
    Drops the Windows Firewall guillotine. 
    Blocks all inbound and outbound traffic to stop data exfiltration and C2 communication.
    """
    if not is_admin():
        print("\n[-] ISOLATION FAILED: Administrator privileges required.")
        print("[-] To enable Automated Network Containment, run your terminal as Administrator.")
        return False

    try:
        print("[*] Engaging Network Containment Protocol...")
        
        # PRODUCTION UX FIX: CREATE_NO_WINDOW prevents the cmd.exe window from flashing
        creation_flags = 0
        if os.name == 'nt':
            creation_flags = subprocess.CREATE_NO_WINDOW
            
        subprocess.run(
            ["netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,blockoutbound"], 
            check=True, 
            capture_output=True, 
            text=True,
            creationflags=creation_flags
        )
        print("[+] SUCCESS: Host isolated. All outbound network traffic is now blocked.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[-] FATAL: Firewall modification failed. The OS may have locked the configuration: {e}")
        return False
    except FileNotFoundError:
        print("[-] FATAL: 'netsh' utility not found. Host OS may be corrupted.")
        return False

def restore_network():
    """
    The Escape Hatch. Restores the Windows Firewall back to its default state
    (Block Inbound, Allow Outbound).
    """
    if not is_admin():
        print("\n[-] RESTORE FAILED: Administrator privileges required.")
        return False

    try:
        print("[*] Disengaging Network Containment Protocol...")
        
        creation_flags = 0
        if os.name == 'nt':
            creation_flags = subprocess.CREATE_NO_WINDOW
            
        subprocess.run(
            ["netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,allowoutbound"], 
            check=True, 
            capture_output=True, 
            text=True,
            creationflags=creation_flags
        )
        print("[+] SUCCESS: Network connectivity restored to default enterprise state.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[-] FATAL: Firewall restoration failed: {e}")
        return False