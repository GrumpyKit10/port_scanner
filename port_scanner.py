# port_scanner.py
# By Matthew Wilson
# 12/20/25
# This program is for educational purposes only. 
# Topics: TCP/UDP, Sockets, Timeouts, Error Handling, Firewalls, Multithreading, Service/Banner Detection, CIDR range scanning.
# TODO:
#   - Rewrite in Go
#   - Use argparse for CLI args - DONE (12/20/25)
#   - Add port ranges - DONE (12/20/25)
#   - Output formatting / Output modes (quiet - DONE (12/30/25), grepable - DONE (12/31/2025), JSON  - DONE (12/31/2025), CSV  - DONE (12/31/2025), full packet - DONE (12/30/25)) 
#   - Make all args optional - DONE (12/31/2025)
#   - Better arg help message (add usage) - DONE (12/31/2025)
#   - Batching - DONE (12/30/25)
#   - Use socket for banners with scapy - DONE (12/30/25)
#   - ICMP filtered handling - DONE (12/30/25)
#   - CIDR expansion - DONE (12/31/2025) / progress reporting - DONE (12/31/2025)
#   - Use Scapy for SYN mode and full packet output - DONE (12/30/25)
#   - Threading for banners - DONE (12/31/2025)
#   - Batch randomization for stealth - DONE (12/31/2025)
#
# Example Usage Goal: sudo python3 port_scanner.py -t scanme.nmap.org -p 1-1024 -v 2 -b 200 -o grep -r
#
# Issues: 

import os
from scapy.all import IP, TCP, sr, sr1, hexdump
from scapy.layers.inet import ICMP
import socket
import sys
import json
import csv
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress
import signal
import time
import random

start_time = time.time()

stop_scan = False

progress_active = False

MAX_BANNER_THREADS = 10

parser = argparse.ArgumentParser(
    description=(
        "TCP SYN port scanner using Scapy (educational use).\n"
        "Supports CIDR expansion, batching, randomization, banner grabbing,\n"
        "and multiple output formats."
    ),
    epilog=(
        "Examples:\n"
        "  sudo python3 port_scanner.py -t scanme.nmap.org\n"
        "  sudo python3 port_scanner.py -t 192.168.1.1 -p 22,80,443\n"
        "  sudo python3 port_scanner.py -t 192.168.1.0/24 -p 22 -r\n"
        "  sudo python3 port_scanner.py -t example.com -p 1-1024 -o json\n"
        "  sudo python3 port_scanner.py -t localhost -p 80 -v 4\n"
    ),
    formatter_class=argparse.RawDescriptionHelpFormatter
)

parser.add_argument(
    "-t", "--target",
    default="scanme.nmap.org",
    metavar="HOST",
    help=(
        "Target to scan.\n"
        "Accepted formats:\n"
        "  - Hostname (example.com)\n"
        "  - Single IP (192.168.1.10)\n"
        "  - CIDR range (192.168.1.0/24)\n"
        "Default: scanme.nmap.org"
    )
)

parser.add_argument(
    "-p", "--ports",
    default="1-1024",
    metavar="PORTS",
    help=(
        "Ports to scan.\n"
        "Supported formats:\n"
        "  80\n"
        "  22,80,443\n"
        "  1-1024\n"
        "  1-1024,3306,8080\n"
        "Default: 1-1024"
    )
)

parser.add_argument(
    "-v", "--verbose",
    type=int,
    default=1,
    choices=[0, 1, 2, 4],
    metavar="LEVEL",
    help=(
        "Verbosity level:\n"
        "  0 = quiet (open ports only)\n"
        "  1 = standard output (default)\n"
        "  2 = detailed progress and debug info\n"
        "  4 = full packet summaries and hex dumps"
    )
)

parser.add_argument(
    "-b", "--batch",
    type=int,
    default=50,
    metavar="N",
    help=(
        "Number of ports scanned per batch.\n"
        "Smaller values are slower but stealthier.\n"
        "Larger values are faster but noisier.\n"
        "Default: 50"
    )
)

parser.add_argument(
    "-o", "--output",
    choices=["human", "grep", "json", "csv"],
    default="human",
    metavar="FORMAT",
    help=(
        "Output format:\n"
        "  human = readable console output (default)\n"
        "  grep  = one-line-per-result (script friendly)\n"
        "  json  = structured JSON output\n"
        "  csv   = CSV output for spreadsheets or tooling"
    )
)

parser.add_argument(
    "-r", "--randomize",
    action="store_true",
    help=(
        "Randomize host and port order.\n"
        "Reduces scan patterns and increases stealth."
    )
)


cli = vars(parser.parse_args())

output_buffer = []

def handle_sigint(signum, frame):
    global stop_scan
    stop_scan = True
    progress_finish()

signal.signal(signal.SIGINT, handle_sigint)

def vprint(level, *args, **kwargs):
    if cli["output"] == "human" and cli["verbose"] >= level:
        print(*args, **kwargs)

def parse_ports(port_arg):
    ports = set()

    try:
        for part in port_arg.split(","):
            part = part.strip()

            if "-" in part:
                start, end = part.split("-", 1)
                start, end = int(start), int(end)

                if not (1 <= start <= 65535 and 1 <= end <= 65535):
                    raise ValueError

                if start > end:
                    raise ValueError("Start port greater than end port")

                ports.update(range(start, end + 1))

            else:
                port = int(part)
                if not (1 <= port <= 65535):
                    raise ValueError
                ports.add(port)

        if not ports:
            raise ValueError

        return sorted(ports)

    except ValueError:
        vprint(2, "[!] Invalid port specification.")
        sys.exit(2)
    
def scan_ports_batched(ip, ports, batch_size, total_work, completed_work):
    results = {}

    ports = list(ports)
    
    if cli.get("randomize"):
        random.shuffle(ports)

    for i in range(0, len(ports), batch_size):
        if stop_scan:
            return results, completed_work
    
        batch = ports[i:i + batch_size]

        packets = IP(dst=ip) / TCP(dport=batch, flags="S")
        
        try:
            answered, unanswered = sr(packets, timeout=1, verbose=False)
        except PermissionError:
            print("[!] Raw socket permission denied (run as root).")
            sys.exit(1)
        except Exception as e:
            vprint(2, f"[!] Packet send error: {e}")
            return results, completed_work
        
        if cli.get("randomize"):
            time.sleep(random.uniform(0.02, 0.15))
        
        completed_work += len(batch)
        progress_update(
            completed_work,
            total_work,
            prefix=f"[{ip}] "
        )
        
        # Handle answered packets
        for sent, recv in answered:
            if not sent.haslayer(TCP):
                continue
            
            port = sent[TCP].dport

            if recv.haslayer(ICMP):
                icmp = recv[ICMP]
                if icmp.type == 3 and icmp.code in {1,2,3,9,10,13}:
                    # administratively prohibited / unreachable
                    results[port] = ("filtered", recv)
                    continue

            if not recv.haslayer(TCP):
                results[port] = ("unknown", recv)
                continue

            tcp = recv[TCP]

            if tcp.flags == 0x12:  # SYN-ACK
                # Send RST to cleanly close
                rst = IP(dst=ip)/TCP(dport=port, flags="R")
                sr1(rst, timeout=0.3, verbose=False)
                results[port] = ("open", recv)

            elif tcp.flags == 0x14:  # RST-ACK
                results[port] = ("closed", recv)

            else:
                results[port] = ("unknown", recv)

        # Handle unanswered packets
        for pkt in unanswered:
            port = pkt[TCP].dport
            results[port] = ("filtered", None)

    return results, completed_work

def print_packet(packet):
    if cli["verbose"] >= 4 and packet:
        print(packet.summary())
        hexdump(packet)
    
def banner_grab(ip, port):
    try:
        with socket.create_connection((ip, port), timeout=2) as s:
            banner = s.recv(1024)
            return banner.decode(errors="ignore").strip()
    except (socket.timeout, ConnectionRefusedError):
        return None
    except Exception as e:
        vprint(2, f"[!] Banner error on {port}: {e}")
        return None

def resolve_target(target):
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        vprint(2, f"[!] Unable to resolve target: {target}")
        sys.exit(2)

def expand_target(target):
    """
    Returns a list of IP strings.
    Supports:
      - hostname
      - single IP
      - CIDR (e.g. 192.168.1.0/24)
    """
    try:
        # CIDR case
        if "/" in target:
            net = ipaddress.ip_network(target, strict=False)

            # Skip network + broadcast for IPv4
            if net.version == 4:
                return [str(ip) for ip in net.hosts()]
            else:
                return [str(ip) for ip in net]

        # Single IP or hostname
        return [resolve_target(target)]

    except ValueError:
        vprint(2, f"[!] Invalid target: {target}")
        sys.exit(2)

def emit_result(target, port, state, banner=None):
    fmt = cli["output"]
    
    record = {
        "target": target,
        "port": port,
        "protocol": "tcp",
        "state": state,
        "banner": banner or ""
    }

    if fmt == "human":
        if state == "open":
            vprint(0, f"[+] Port {port} open")
            if banner:
                vprint(2, f"    Banner: {banner}")

    elif fmt == "grep":
        if state == "open":
            line = f"{target} {port}/tcp {state}"
            if banner:
                line += f" {banner}"
            print(line)


    elif fmt in ("json", "csv"):
        output_buffer.append(record)
    
def emit_structured_output():
    fmt = cli["output"]

    if fmt == "json":
        # Pretty-printed JSON with no extra spaces
        print(json.dumps(output_buffer, indent=2, separators=(',', ': ')))

    elif fmt == "csv":
        # Ensure no extra blank lines in CSV
        writer = csv.DictWriter(
            sys.stdout,
            fieldnames=["target", "port", "protocol", "state", "banner"],
            lineterminator="\n"  # important: prevents extra blank lines
        )
        writer.writeheader()
        for row in output_buffer:
            # Strip whitespace from banner to remove accidental spaces
            row["banner"] = row["banner"].strip()
            writer.writerow(row)

def progress_update(done, total, prefix=""):
    global progress_active

    percent = (done / total) * 100
    elapsed = time.time() - start_time
    rate = done / elapsed if elapsed > 0 else 0
    eta = (total - done) / rate if rate > 0 else 0

    progress_active = True

    sys.stderr.write(
        f"\r{prefix}{done}/{total} "
        f"({percent:5.1f}%) | "
        f"{rate:6.1f} ops/sec | "
        f"ETA {eta:5.1f}s"
    )
    sys.stderr.flush()

def progress_finish():
    global progress_active
    if progress_active:
        sys.stderr.write("\n")
        sys.stderr.flush()
        progress_active = False
    
def main():
    if os.geteuid() != 0:
        vprint(1, "[!] Root privileges required (run with sudo).")
        sys.exit(1)
    
    if cli["batch"] < 1:
        vprint(1, "[!] Batch size must be >= 1")
        sys.exit(2)
    
    try: 
        targets = expand_target(cli["target"])
        
        if cli["randomize"]:
            random.shuffle(targets)
            
        ports = parse_ports(cli["ports"])
        
        total_hosts = len(targets)
        total_ports = len(ports)
        total_work = total_hosts * total_ports
        completed_work = 0

        host_count = 0

        for ip in targets:
            if stop_scan:
                vprint(1, "[*] Scan aborted by user")
                break
            
            host_count += 1

            vprint(
                1,
                f"[*] Scanning {ip} ({host_count}/{total_hosts})"
            )

            results, completed_work = scan_ports_batched(
                ip,
                ports,
                cli["batch"],
                total_work,
                completed_work
            )
            
            open_ports = sorted(p for p, (s, _) in results.items() if s == "open")

            if cli["verbose"] >= 2:
                
                progress_finish()
                
                with ThreadPoolExecutor(max_workers=MAX_BANNER_THREADS) as executor:
                    if stop_scan:
                        break

                    futures = {
                        executor.submit(banner_grab, ip, port): port
                        for port in open_ports
                    }

                    for future in as_completed(futures):
                        port = futures[future]
                        banner = future.result()
                        state, packet = results[port]

                        emit_result(ip, port, state, banner)
                        print_packet(packet)
                
            else:
                for port in open_ports:
                    state, _ = results[port]
                    emit_result(ip, port, state, None)
                    
        progress_finish()

        emit_structured_output()
    
    except Exception as e:
        vprint(2, f"[!] Fatal error: {e}")
        sys.exit(1)
        
    if not stop_scan:
        vprint(1, "[*] Scan complete") # Indicates the scan finished successfully.

if __name__ == "__main__":
    # ensures main() only runs when the script is executed directly.
    # not when imported as a module. 
    main()
