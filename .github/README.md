# 🔍 IP Freely — Network Scanner

A Python command-line tool that scans all host addresses within a given CIDR network range using ICMP ping. Built for a network programming assignment covering subnetting, ping, reverse DNS, and MAC address detection.

> ⚠️ **Legal Notice:** Network scanning can be considered hostile behavior. Only scan networks you own or have explicit permission to test.

---

## Features

- Accepts any valid CIDR notation (e.g. `192.168.1.0/24`)
- Calculates the full host range from the subnet mask
- Pings every host concurrently for fast scans
- Reports status (`UP` / `DOWN` / `ERROR`), response time in ms, and error messages
- Colorized terminal output
- **Extra credit:** Reverse DNS lookup, MAC address detection, and CSV export

---

## Requirements

- Python 3.9 or higher
- No third-party libraries — uses the standard library only
- `ping` must be available on your system (it is by default on Windows, macOS, and Linux)
- MAC address detection requires the `arp` command (available by default on all major OS)

---

## Usage

### Basic scan
```bash
python ip_freely.py <network>
```

```bash
python ip_freely.py 192.168.1.0/24
```

### Enable extra features (DNS + MAC)
```bash
python ip_freely.py 192.168.1.0/24 --extra
```

### Export results to CSV
```bash
python ip_freely.py 192.168.1.0/24 --csv results.csv
```

### All options combined
```bash
python ip_freely.py 192.168.1.0/24 --extra --csv results.csv --threads 100
```

---

## Options

| Flag | Description | Default |
|------|-------------|---------|
| `network` | Network in CIDR notation *(required)* | — |
| `--extra` | Enable reverse DNS lookup and MAC address detection | Off |
| `--csv FILE` | Export results to a CSV file | Off |
| `--threads N` | Number of concurrent scan threads | 50 |

---

## Example Output

### Basic
```
  IP Freely — Network Scanner
  ──────────────────────────────────────────────────
  Network  : 192.168.1.0/24
  Hosts    : 254
  Started  : 2025-03-01 14:22:05
  ──────────────────────────────────────────────────

  192.168.1.1    - UP   (2ms)
  192.168.1.2    - DOWN (No response)
  192.168.1.3    - UP   (5ms)
  192.168.1.4    - UP   (3ms)
  192.168.1.5    - ERROR (Connection timeout)

  ──────────────────────────────────────────────────
  Scan complete. Found 3 active, 1 down, 1 error(s).
  ──────────────────────────────────────────────────
```

### With `--extra`
```
  192.168.1.1    - UP   (2ms)
    Hostname:    router.local
    MAC:         00:11:22:33:44:55

  192.168.1.2    - DOWN (No response)

  192.168.1.3    - UP   (5ms)
    Hostname:    printer.local
    MAC:         AA:BB:CC:DD:EE:FF

  Results exported to scan_results.csv
```

---

## CSV Output

When `--csv` is used, a file is created with the following columns:

| Column | Description |
|--------|-------------|
| `ip` | IP address |
| `status` | UP, DOWN, or ERROR |
| `ms` | Response time in milliseconds |
| `hostname` | Reverse DNS result (if `--extra`) |
| `mac` | MAC address (if `--extra`) |
| `error` | Error message if status is ERROR |

---

## How It Works

1. The CIDR input (e.g. `192.168.1.0/24`) is parsed using Python's built-in `ipaddress` module to calculate all valid host addresses in the range.
2. Each host is pinged concurrently using a thread pool, calling the OS-level `ping` command as a subprocess.
3. If `--extra` is enabled, a reverse DNS lookup is performed via `socket.gethostbyaddr()`, and the MAC address is read from the OS ARP cache (populated automatically after a successful ping).
4. Results are printed to the terminal in sorted order and optionally written to a CSV file.

---

## Notes

- On some systems, `ping` may require administrator or root privileges to send ICMP packets.
- MAC address detection only works for hosts on the **same local network segment** — routers do not expose MAC addresses of remote hosts.
- Reverse DNS lookups depend on your network's DNS configuration and may not return results for all hosts.