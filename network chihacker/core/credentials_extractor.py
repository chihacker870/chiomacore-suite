# ==========================================
# ChiomaCore Suite - Credentials Extractor Utility
# For educational and authorized use only
# ==========================================
#
# This tool is part of the ChiomaCore Suite.
# Use only on systems you own or have explicit permission to test.
# Unauthorized use is strictly prohibited.
#
# For support, visit: https://github.com/chiomacore
# ==========================================

import os
import sys
import re
import colorama
from colorama import Fore, Style
colorama.init(autoreset=True)
from datetime import datetime

def banner():
    print(Fore.GREEN + Style.BRIGHT + """
    ==========================================
    |   ChiomaCore Suite Credentials Extractor |
    |         For authorized use only         |
    ==========================================
    """)

def print_status(message, color=Fore.CYAN):
    print(color + f"[ChiomaCore Suite] {message}")

def print_help():
    print(Fore.YELLOW + """
    Usage:
      - Run the script and follow prompts.
      - Specify the file or directory to scan for credentials.
      - Only use on systems you own or have permission to test.
    """)

def find_credentials_in_file(filepath):
    """Scan a file for patterns that look like credentials."""
    patterns = [
        r'password\s*=\s*[\'"]?([^\'"\s]+)[\'"]?',   # password = 'something'
        r'pwd\s*=\s*[\'"]?([^\'"\s]+)[\'"]?',        # pwd = 'something'
        r'pass\s*:\s*[\'"]?([^\'"\s]+)[\'"]?',       # pass: 'something'
        r'username\s*=\s*[\'"]?([^\'"\s]+)[\'"]?',   # username = 'something'
        r'user\s*=\s*[\'"]?([^\'"\s]+)[\'"]?',       # user = 'something'
        r'api[_-]?key\s*=\s*[\'"]?([^\'"\s]+)[\'"]?',# api_key = 'something'
        r'secret\s*=\s*[\'"]?([^\'"\s]+)[\'"]?',     # secret = 'something'
    ]
    found = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
            for idx, line in enumerate(lines):
                for pat in patterns:
                    match = re.search(pat, line, re.IGNORECASE)
                    if match:
                        found.append((idx+1, line.strip()))
    except Exception as e:
        print_status(f"Error reading {filepath}: {e}", Fore.RED)
    return found

def scan_directory(directory):
    """Recursively scan a directory for files and extract credentials."""
    credentials = {}
    for root, _, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            found = find_credentials_in_file(filepath)
            if found:
                credentials[filepath] = found
    return credentials

def show_results(results):
    if not results:
        print_status("No credentials found.", Fore.GREEN)
        return
    print(Fore.CYAN + "\n[ChiomaCore Suite] Possible credentials found:")
    for filepath, matches in results.items():
        print(Fore.YELLOW + f"\nFile: {filepath}")
        for lineno, line in matches:
            print(Fore.MAGENTA + f"  Line {lineno}: {line}")

def about():
    print(Fore.CYAN + """
    ==========================================
    ChiomaCore Suite - Credentials Extractor
    Version: 1.0.0
    Author: ChiomaCore Team
    License: For educational and authorized use only.
    ==========================================
    """)

def disclaimer():
    print(Fore.RED + """
    [!] WARNING: Unauthorized use of this tool is illegal.
    Use only for educational purposes and on systems you own or have permission to test.
    """)

def credits():
    print(Fore.GREEN + """
    ==========================================
    Credits:
    - ChiomaCore Team
    - colorama (terminal color library)
    ==========================================
    """)

def exit_message():
    print(Fore.CYAN + "\n[ChiomaCore Suite] Thank you for using the Credentials Extractor Utility.")
    print(Fore.CYAN + "[ChiomaCore Suite] Stay safe and use responsibly!")
    print(Fore.CYAN + "[ChiomaCore Suite] Goodbye!\n")

if __name__ == "__main__":
    banner()
    print_help()
    disclaimer()
    path = input(Fore.CYAN + "[ChiomaCore Suite] Enter file or directory to scan: ").strip()
    if not os.path.exists(path):
        print_status("Specified path does not exist. Exiting.", Fore.RED)
        sys.exit(1)
    start_time = datetime.now()
    if os.path.isfile(path):
        results = {}
        found = find_credentials_in_file(path)
        if found:
            results[path] = found
        show_results(results)
    elif os.path.isdir(path):
        results = scan_directory(path)
        show_results(results)
    else:
        print_status("Invalid path. Exiting.", Fore.RED)
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()
    print(Fore.CYAN + f"\n[ChiomaCore Suite] Scan duration: {duration:.2f} seconds")
    credits()
    exit_message()