# This is the live EDR module that allows users to scan active processes in memory. 
# It enumerates active processes, filters out system binaries, and allows the user to select a process to scan.
import os
import psutil

def get_target_process_path() -> str:
    """
    EDR Module: Enumerates active RAM for non-system executables.
    Returns the physical file path of the user-selected PID, or None.
    """
    print("\n--- Live Process Memory Triage ---")
    print("[*] Enumerating active processes...")

    suspicious_procs = []
    
    # Iterate through running process memory allocation
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            exe_path = proc.info['exe']
            # BLUE TEAM SAFEGUARD: Exclude Windows Core OS binaries
            if exe_path and "C:\\Windows" not in exe_path:
                suspicious_procs.append({
                    'pid': proc.info['pid'],
                    'name': proc.info['name'],
                    'path': exe_path
                })
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            # Gracefully ignore SYSTEM protected memory chunks
            continue

    if not suspicious_procs:
        print("[+] No non-system processes found. System appears clean.")
        return None

    # Format the terminal table
    print(f"\n{'PID':<10} | {'Process Name':<25} | {'Executable Path'}")
    print("-" * 80)
    
    # Display the 20 most recently instantiated processes
    for p in suspicious_procs[-20:]: 
        display_path = p['path'] if len(p['path']) < 40 else "..." + p['path'][-37:]
        print(f"{p['pid']:<10} | {p['name']:<25} | {display_path}")

    # Process Selection
    choice = input("\n[?] Enter the PID of the process to scan (or press Enter to cancel): ").strip()
    if not choice.isdigit():
        return None

    target_pid = int(choice)
    
    # Extract physical disk path linked to the active PID
    for p in suspicious_procs:
        if p['pid'] == target_pid:
            if os.path.exists(p['path']):
                return p['path']
                
    print("[-] Invalid PID or the process terminated before scanning.")
    return None