# ==========================================
# ChiomaCore Suite - Packet Sniffer Utility
# For educational and authorized use only
# ==========================================
#
# This tool is part of the ChiomaCore Suite.
# Use only on networks you own or have explicit permission to test.
# Unauthorized use is strictly prohibited.
#
# For support, visit: https://github.com/chiomacore
# ==========================================

import sys
from datetime import datetime
import colorama
from colorama import Fore, Style
colorama.init(autoreset=True)
from scapy.all import sniff, hexdump, IP, TCP, UDP, ARP

def banner():
    print(Fore.GREEN + Style.BRIGHT + """
    ==========================================
    |    ChiomaCore Suite Packet Sniffer     |
    |         For authorized use only        |
    ==========================================
    """)

def print_status(message, color=Fore.CYAN):
    print(color + f"[ChiomaCore Suite] {message}")

def print_help():
    print(Fore.YELLOW + """
    Usage:
      - Run the script and follow prompts.
      - Select the correct network interface (or leave blank for default).
      - Press Ctrl+C to stop sniffing.
    """)

def packet_callback(pkt):
    print(Fore.CYAN + f"\n[ChiomaCore Suite] Packet captured at {datetime.now().strftime('%H:%M:%S')}")
    if IP in pkt:
        ip_layer = pkt[IP]
        print(Fore.YELLOW + f"  From: {ip_layer.src} -> To: {ip_layer.dst}")
        print(Fore.YELLOW + f"  Protocol: {ip_layer.proto}")
    if TCP in pkt:
        tcp_layer = pkt[TCP]
        print(Fore.MAGENTA + f"  TCP | Src Port: {tcp_layer.sport} -> Dst Port: {tcp_layer.dport}")
    if UDP in pkt:
        udp_layer = pkt[UDP]
        print(Fore.MAGENTA + f"  UDP | Src Port: {udp_layer.sport} -> Dst Port: {udp_layer.dport}")
    if ARP in pkt:
        arp_layer = pkt[ARP]
        print(Fore.MAGENTA + f"  ARP | {arp_layer.psrc} is-at {arp_layer.hwsrc}")
    print(Fore.WHITE + "  Raw Data:")
    hexdump(pkt)

def about():
    print(Fore.CYAN + """
    ==========================================
    ChiomaCore Suite - Packet Sniffer
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
    print(Fore.CYAN + "\n[ChiomaCore Suite] Thank you for using the Packet Sniffer Utility.")
    print(Fore.CYAN + "[ChiomaCore Suite] Stay safe and use responsibly!")
    print(Fore.CYAN + "[ChiomaCore Suite] Goodbye!\n")

if __name__ == "__main__":
    banner()
    print_help()
    disclaimer()
    iface = input(Fore.CYAN + "[ChiomaCore Suite] Enter interface to sniff (leave blank for default): ").strip()
    print_status("Starting packet capture... Press Ctrl+C to stop.", Fore.CYAN)
    try:
        sniff(prn=packet_callback, iface=iface if iface else None, store=0)
    except KeyboardInterrupt:
        print_status("\nStopping packet capture...", Fore.YELLOW)
    credits()
    exit_message()