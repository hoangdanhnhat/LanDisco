# 🌐 Network Device Discovery Script

A Python script that discovers devices on your local network and displays them in a beautiful table format.

## Features

- Automatically scans local network interfaces
- Discovers active devices with IP, hostname, MAC address, vendor info
- Detects open ports and measures response times
- Cross-platform (Windows, Linux, macOS)
- Multi-threaded for fast scanning

## Installation

```bash
pip install -r requirements.txt
```

**Requirements:**
- Python 3.7+
- `rich`, `netifaces`, `psutil` (installed via requirements.txt)

## Usage

```bash
# Basic scan
python network_scanner.py

# Quick scan (no port scanning)
python network_scanner.py --quick

# Custom thread count
python network_scanner.py --threads 20
```

## Command Options

| Option | Description | Default |
|--------|-------------|---------|
| `--threads`, `-t` | Number of scanning threads | 30 |
| `--quick`, `-q` | Skip port scanning for speed | False |

## Sample Output

```
┏━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━━┓
┃ IP Address    ┃ Hostname          ┃ MAC Address       ┃ Vendor      ┃ Open Ports┃
┡━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━━┩
│ 192.168.1.1   │ router.local      │ AA:BB:CC:DD:EE:FF │ Netgear     │ 80, 443   │
│ 192.168.1.100 │ desktop-pc        │ 11:22:33:44:55:66 │ Intel       │ 3389      │
└───────────────┴───────────────────┴───────────────────┴─────────────┴───────────┘
```

## Troubleshooting

**Script hangs:** Use `--quick` mode or reduce threads with `--threads 10`

**No devices found:** Run with administrator/root privileges for better results

**Permission errors:** 
- Linux/Mac: `sudo python network_scanner.py`
- Windows: Run as Administrator