# ==========================================
# ChiomaCore Suite - Network Scanner Utility
# For educational and authorized use only
# ==========================================
#
# This tool is part of the ChiomaCore Suite.
# Use only on networks you own or have explicit permission to test.
# Unauthorized use is strictly prohibited.
#
# For support, visit: https://github.com/chiomacore
# ==========================================

import os
import sys
from datetime import datetime
import colorama
from colorama import Fore, Style
colorama.init(autoreset=True)
from scapy.all import ARP, Ether, srp

def banner():
    print(Fore.GREEN + Style.BRIGHT + """
    ==========================================
    |    ChiomaCore Suite Network Scanner    |
    |         For authorized use only        |
    ==========================================
    """)

def print_status(message, color=Fore.CYAN):
    print(color + f"[ChiomaCore Suite] {message}")

def print_help():
    print(Fore.YELLOW + """
    Usage:
      - Run the script and follow prompts.
      - Enter the target IP range (e.g., 192.168.1.1/24).
      - Only use on networks you own or have permission to test.
    """)

def scan_network(target):
    """Scan the network for live hosts using ARP requests."""
    print_status(f"Scanning network: {target}")
    arp = ARP(pdst=target)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    result = srp(packet, timeout=2, verbose=0)[0]
    clients = []
    for sent, received in result:
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})
    return clients

def show_results(clients):
    if not clients:
        print_status("No devices found.", Fore.GREEN)
        return
    print(Fore.CYAN + "\n[ChiomaCore Suite] Devices found:")
    print(Fore.YELLOW + "IP" + " " * 18 + "MAC")
    print(Fore.YELLOW + "-" * 35)
    for client in clients:
        print(Fore.MAGENTA + f"{client['ip']:16}    {client['mac']}")

def about():
    print(Fore.CYAN + """
    ==========================================
    ChiomaCore Suite - Network Scanner
    Version: 1.0.0
    Author: ChiomaCore Team
    License: For educational and authorized use only.
    ==========================================
    """)

def disclaimer():
    print(Fore.RED + """
    [!] WARNING: Unauthorized use of this tool is illegal.
    Use only for educational purposes and on networks you own or have permission to test.
    """)

def credits():
    print(Fore.GREEN + """
    ==========================================
    Credits:
    - ChiomaCore Team
    - scapy (packet manipulation library)
    - colorama (terminal color library)
    ==========================================
    """)

def exit_message():
    print(Fore.CYAN + "\n[ChiomaCore Suite] Thank you for using the Network Scanner Utility.")
    print(Fore.CYAN + "[ChiomaCore Suite] Stay safe and use responsibly!")
    print(Fore.CYAN + "[ChiomaCore Suite] Goodbye!\n")

if __name__ == "__main__":
    banner()
    print_help()
    disclaimer()
    target = input(Fore.CYAN + "[ChiomaCore Suite] Enter target IP range (e.g., 192.168.1.1/24): ").strip()
    if not target:
        print_status("No target specified. Exiting.", Fore.RED)
        sys.exit(1)
    start_time = datetime.now()
    clients = scan_network(target)
    show_results(clients)
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()
    print(Fore.CYAN + f"\n[ChiomaCore Suite] Scan duration: {duration:.2f} seconds")
    credits()
    exit_message()