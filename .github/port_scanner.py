#!/usr/bin/env python3
"""
ip_freely.py - Network IP Scanner
Scans all host addresses in a given CIDR network range using ping,
with optional reverse DNS lookup, MAC address detection, and CSV export.

Usage:
    python ip_freely.py 192.168.1.0/24
    python ip_freely.py 10.0.0.0/28 --csv results.csv
"""

import sys
import subprocess
import ipaddress
import socket
import time
import platform
import csv
import argparse
import re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed


#Colour helpers 
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"


def colour(text: str, code: str) -> str:
    """Wrap text in an ANSI colour code."""
    return f"{code}{text}{RESET}"


#Ping 

def ping(ip: str, timeout: int = 1) -> tuple[str, float | None]:
    """
    Send a single ICMP ping to *ip*.

    Returns
    -------
    status : "UP" | "DOWN" | "ERROR"
    ms     : round-trip time in milliseconds, or None
    """
    os_name = platform.system().lower()

    # Build the platform-appropriate ping command
    if os_name == "windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout * 1000), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(timeout), ip]

    start = time.perf_counter()
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout + 1,
        )
        elapsed_ms = (time.perf_counter() - start) * 1000

        if result.returncode == 0:
            return "UP", round(elapsed_ms, 1)
        else:
            return "DOWN", None

    except subprocess.TimeoutExpired:
        return "ERROR", None
    except Exception:
        return "ERROR", None


#Reverse DNS 

def reverse_dns(ip: str, timeout: float = 2.0) -> str | None:
    """Return the hostname for *ip*, or None if lookup fails."""
    try:
        socket.setdefaulttimeout(timeout)
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return None


#MAC Address 

def get_mac(ip: str) -> str | None:
    """
    Attempt to read the MAC address for *ip* from the OS ARP cache.
    Works on Linux/macOS (arp -n) and Windows (arp -a).
    The host must have been pinged recently so its entry is cached.
    """
    os_name = platform.system().lower()
    try:
        if os_name == "windows":
            cmd = ["arp", "-a", ip]
        else:
            cmd = ["arp", "-n", ip]

        result = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3
        )
        output = result.stdout.decode()

        # Match a MAC address pattern (both XX:XX:XX and XX-XX-XX formats)
        mac_match = re.search(
            r"([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}", output
        )
        if mac_match:
            return mac_match.group(0).upper().replace("-", ":")
    except Exception:
        pass
    return None


#Per-host scan 

def scan_host(ip: str, extra: bool = False) -> dict:
    """
    Scan a single host and return a result dict.

    Parameters
    ----------
    ip    : IP address string
    extra : if True, also perform DNS lookup and MAC detection
    """
    status, ms = ping(str(ip))

    result = {
        "ip":       str(ip),
        "status":   status,
        "ms":       ms,
        "hostname": None,
        "mac":      None,
        "error":    None,
    }

    if status == "UP" and extra:
        result["hostname"] = reverse_dns(str(ip))
        result["mac"]      = get_mac(str(ip))
    elif status == "ERROR":
        result["error"] = "Connection timeout"

    return result


#Pretty print 

def format_result(r: dict, extra: bool) -> str:
    """Format a single host result for terminal output."""
    ip_col = f"{r['ip']:<18}"

    if r["status"] == "UP":
        status_col = colour(f"UP   ({r['ms']}ms)", GREEN)
    elif r["status"] == "DOWN":
        status_col = colour("DOWN (No response)", RED)
    else:
        msg = r["error"] or "Unknown error"
        status_col = colour(f"ERROR ({msg})", YELLOW)

    line = f"  {ip_col} - {status_col}"

    if extra and r["status"] == "UP":
        if r["hostname"]:
            line += f"\n    {'Hostname:':<12} {r['hostname']}"
        if r["mac"]:
            line += f"\n    {'MAC:':<12} {r['mac']}"

    return line


#CSV export
def export_csv(results: list[dict], path: str) -> None:
    """Write scan results to a CSV file."""
    fields = ["ip", "status", "ms", "hostname", "mac", "error"]
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(results)
    print(colour(f"\n  Results exported to {path}", CYAN))


#Main

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Scan IP addresses within a CIDR network range."
    )
    parser.add_argument(
        "network",
        help="Network in CIDR notation, e.g. 192.168.1.0/24",
    )
    parser.add_argument(
        "--csv",
        metavar="FILE",
        help="Export results to a CSV file (e.g. --csv results.csv)",
        default=None,
    )
    parser.add_argument(
        "--extra",
        action="store_true",
        help="Enable reverse DNS lookup and MAC address detection",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=50,
        help="Number of concurrent threads (default: 50)",
    )
    args = parser.parse_args()

    # Validate the network
    try:
        network = ipaddress.IPv4Network(args.network, strict=False)
    except ValueError as e:
        print(colour(f"Error: {e}", RED))
        sys.exit(1)

    hosts = list(network.hosts())
    total = len(hosts)

    if total == 0:
        print(colour("No host addresses in that network.", YELLOW))
        sys.exit(0)

    # Header
    print()
    print(colour(f"  {BOLD}IP Freely — Network Scanner", CYAN + BOLD))
    print(colour(f"  {'─' * 50}", CYAN))
    print(f"  Network  : {colour(str(network), BOLD)}")
    print(f"  Hosts    : {colour(str(total), BOLD)}")
    print(f"  Started  : {colour(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), BOLD)}")
    if args.extra:
        print(f"  Extras   : {colour('Reverse DNS  •  MAC lookup', BOLD)}")
    print(colour(f"  {'─' * 50}", CYAN))
    print()

    results   = []
    up_count  = 0
    down_count = 0
    err_count  = 0

    # Scan concurrently
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {
            executor.submit(scan_host, str(h), args.extra): str(h)
            for h in hosts
        }

        # Collect in submission order so output is sorted by IP
        ordered_results = {}
        for future in as_completed(futures):
            r = future.result()
            ordered_results[r["ip"]] = r

    # Print in sorted order
    for h in hosts:
        r = ordered_results[str(h)]
        results.append(r)
        print(format_result(r, args.extra))

        if r["status"] == "UP":
            up_count += 1
        elif r["status"] == "DOWN":
            down_count += 1
        else:
            err_count += 1

    # Summary
    print()
    print(colour(f"  {'─' * 50}", CYAN))
    print(
        f"  Scan complete. "
        f"Found {colour(str(up_count) + ' active', GREEN)}, "
        f"{colour(str(down_count) + ' down', RED)}, "
        f"{colour(str(err_count) + ' error(s)', YELLOW)}."
    )
    print(colour(f"  {'─' * 50}", CYAN))
    print()

    # Optional CSV export
    if args.csv:
        export_csv(results, args.csv)


if __name__ == "__main__":
    main()