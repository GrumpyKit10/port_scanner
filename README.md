# TCP SYN Port Scanner

**Author:** Matthew Wilson
**GitHub:** [https://github.com/GrumpyKit10](https://github.com/GrumpyKit10)
**Date:** 12/20/25
**Language:** Python 3

---

## Description

A TCP SYN port scanner built with Scapy for educational purposes. This tool supports:

* Scanning single IPs, hostnames, and CIDR ranges
* Port range specifications (single, comma-separated, and hyphenated ranges)
* Multi-threaded banner grabbing
* Batch scanning with optional randomization for stealth
* Multiple output formats: human-readable, grepable, JSON, CSV
* Verbosity levels for detailed progress and debugging
* ICMP filtered port handling

This scanner is designed for learning and ethical testing only. Do not use it on unauthorized systems.

---

## Installation

1. Clone the repository:

```bash
git clone https://github.com/GrumpyKit10/port_scanner.git
cd port_scanner
```

2. Install dependencies:

```bash
pip3 install scapy
```

3. Run as root (required for raw socket operations):

```bash
sudo python3 port_scanner.py
```

---

## Usage

```bash
sudo python3 port_scanner.py -t TARGET -p PORTS -v VERBOSE -b BATCH -o OUTPUT -r
```

### Arguments

* `-t, --target`: Target to scan (hostname, IP, CIDR). Default: `scanme.nmap.org`
* `-p, --ports`: Ports to scan (`80`, `22,80,443`, `1-1024`). Default: `1-1024`
* `-v, --verbose`: Verbosity level (0=quiet, 1=standard, 2=detailed, 4=full packets). Default: `1`
* `-b, --batch`: Number of ports scanned per batch. Default: `50`
* `-o, --output`: Output format (`human`, `grep`, `json`, `csv`). Default: `human`
* `-r, --randomize`: Randomize host and port order for stealth.

### Examples

```bash
sudo python3 port_scanner.py -t scanme.nmap.org
sudo python3 port_scanner.py -t 192.168.1.1 -p 22,80,443
sudo python3 port_scanner.py -t 192.168.1.0/24 -p 22 -r
sudo python3 port_scanner.py -t example.com -p 1-1024 -o json
sudo python3 port_scanner.py -t localhost -p 80 -v 4
```

---

## Features

* **CIDR expansion**: Scan all hosts in a network range.
* **Batch scanning**: Control scan size per batch.
* **Randomization**: Reduce scan patterns for stealth.
* **Banner grabbing**: Detect service information on open ports.
* **Structured output**: JSON/CSV for easy integration.
* **Progress reporting**: Shows progress, ops/sec, ETA even in non-human outputs.
* **Interrupt handling**: Ctrl+C safely stops the scan.

---

## Warning

This tool is for **educational and authorized penetration testing only**. Unauthorized scanning may violate laws and policies.

---

## License

MIT License
