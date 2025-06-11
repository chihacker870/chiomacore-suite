# ==========================================
# ChiomaCore Suite - Main Launcher
# For educational and authorized use only
# ==========================================
#
# This launcher is part of the ChiomaCore Suite.
# Use only on systems you own or have explicit permission to test.
# Unauthorized use is strictly prohibited.
#
# For support, visit: https://github.com/chiomacore
# ==========================================

import os
import sys
import subprocess
import colorama
from colorama import Fore, Style
import socket

colorama.init(autoreset=True)

def banner():
    print(Fore.GREEN + Style.BRIGHT + """
    ==========================================
    |         ChiomaCore Suite Launcher      |
    |         For authorized use only        |
    ==========================================
    """)

def print_menu():
    print(Fore.CYAN + """
    [1] Network Scanner
    [2] ARP Spoofer
    [3] DNS Spoofer
    [4] Packet Sniffer
    [5] Credentials Extractor
    [6] Dashboard (GUI)
    [0] Exit
    """)

def run_script(script_path):
    if not os.path.exists(script_path):
        print(Fore.RED + f"[ChiomaCore Suite] Script not found: {script_path}")
        return
    try:
        subprocess.run([sys.executable, script_path])
    except Exception as e:
        print(Fore.RED + f"[ChiomaCore Suite] Error running {script_path}: {e}")

def main():
    banner()
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    print("Local IP Address:", local_ip)
    while True:
        print_menu()
        choice = input(Fore.YELLOW + "[ChiomaCore Suite] Select an option: ").strip()
        if choice == "1":
            run_script(os.path.join("core", "network_scanner.py"))
        elif choice == "2":
            run_script(os.path.join("core", "arp_spoofer.py"))
        elif choice == "3":
            run_script(os.path.join("core", "dns_spoofer.py"))
        elif choice == "4":
            run_script(os.path.join("core", "packet_sniffer.py"))
        elif choice == "5":
            run_script(os.path.join("core", "credentials_extractor.py"))
        elif choice == "6":
            run_script(os.path.join("UI", "dashboard.py"))
        elif choice == "0":
            print(Fore.CYAN + "[ChiomaCore Suite] Goodbye!")
            break
        else:
            print(Fore.RED + "[ChiomaCore Suite] Invalid option. Please try again.")

if __name__ == "__main__":
    main()