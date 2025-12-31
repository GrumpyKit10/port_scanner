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
#   - Expand port arg to scan common groups of ports (all, common, etc)
#   - Better arg help message (add usage)
#   - Batching - DONE (12/30/25)
#   - Use socket for banners with scapy - DONE (12/30/25)
#   - ICMP filtered handling - DONE (12/30/25)
#   - CIDR expansion / progress reporting
#   - Use Scapy for SYN mode and full packet output - DONE (12/30/25)
#   - Threading for banners?
#
# Example Usage Goal: sudo python3 port_scanner.py -t scanme.nmap.org -p 1-1024 -v 2 -b 200 -o grep
#
# Issues: 
import os

from scapy.all import IP, TCP, sr, sr1, hexdump

from scapy.layers.inet import ICMP

import socket

import sys
# Imports system-specific functions.
# We use this mainly for sys.exit() to cleanly terminate the program.

import json
import csv

import argparse

parser = argparse.ArgumentParser()
parser.add_argument(
    "-t", "--target", 
    default="scanme.nmap.org", 
    help="target ip or hostname to be scanned", 
    required=False
)
parser.add_argument(
    "-p", "--ports", 
    default="1-1024", 
    help="port(s) to be scanned on target", 
    required=False
)
parser.add_argument(
    "-v", "--verbose", 
    type=int, 
    default=1, 
    help="Verbosity level: 0=quiet, 1=normal, 2=more info 4=full packet", 
    required=False
)
parser.add_argument(
    "-b", "--batch", 
    type=int, 
    default=100, 
    help="batch size for port scans", 
    required=False
)
parser.add_argument(
    "-o", "--output",
    choices=["human", "grep", "json", "csv"],
#    type=int, 
    default="human", 
    help="output format: human|grep|json|csv", 
    required=False
)
cli = vars(parser.parse_args())

output_buffer = []

def vprint(level, *args, **kwargs):
    if cli["output"] == "human" and cli["verbose"] >= level:
        print(*args, **kwargs)

def parse_ports(port_arg):
    try:
        if "-" in port_arg:
            start, end = port_arg.split("-", 1)
            start, end = int(start), int(end)
        
            if not (1 <= start <= 65535 and 1 <= end <= 65535):
                raise ValueError
                
            if start > end:
                raise ValueError("Start port greater then end port")
            
            return range(start, end + 1)
        else:
            port = int(port_arg)
            if not (1 <= port <= 65535):
                raise ValueError
            return [port]
    
    except ValueError:
        vprint(2,"[!] Invalid port specification.")
        sys.exit(2)
    
def scan_ports_batched(ip, ports, batch_size):
    results = {}

    ports = list(ports)

    for i in range(0, len(ports), batch_size):
        batch = ports[i:i + batch_size]

        vprint(2, f"[*] Scanning ports {batch[0]}-{batch[-1]}")

        packets = IP(dst=ip) / TCP(dport=batch, flags="S")
        try:
            answered, unanswered = sr(packets, timeout=1, verbose=False)
        except PermissionError:
            print("[!] Raw socket permission denied (run as root).")
            sys.exit(1)
        except Exception as e:
            vprint(2, f"[!] Packet send error: {e}")
            return results

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

    return results

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
                vprint(1, f"    Banner: {banner}")

    elif fmt == "grep":
        # one line, script-friendly
        if state == "open":
            line = f"{target} {port}/tcp {state}"
            if banner:
                line += f" {banner}"
            vprint(0, line)

    elif fmt in ("json", "csv"):
        output_buffer.append(record)

if cli["batch"] < 1:
    vprint(1, "[!] Batch size must be >= 1")
    sys.exit(2)
    
def emit_structured_output():
    fmt = cli["output"]

    if fmt == "json":
        print(json.dumps(output_buffer, indent=2))

    elif fmt == "csv":
        writer = csv.DictWriter(
            sys.stdout,
            fieldnames=["target", "port", "protocol", "state", "banner"]
        )
        writer.writeheader()
        for row in output_buffer:
            writer.writerow(row)

def main():
    if os.geteuid() != 0:
        vprint(1, "[!] Root privileges required (run with sudo).")
        sys.exit(1)
    
    try: 
        ip = resolve_target(cli["target"])
        
        ports = parse_ports(cli["ports"])
        
        vprint(1, f"[*] Scanning {cli['target']} ({ip})")
    
        results = scan_ports_batched(ip, ports, cli["batch"])

        for port in sorted(p for p, (s, _) in results.items() if s == "open"):
            state, packet = results[port]

            banner = banner_grab(ip, port)

            emit_result(cli["target"], port, state, banner)
            print_packet(packet)
              
        emit_structured_output()
        
        open_ports = [p for p, (s, _) in results.items() if s == "open"]
        vprint(1, f"[*] {len(open_ports)} open ports found")        

        vprint(1, "[*] Scan complete")
        # Indicates the scan finished successfully.

    except KeyboardInterrupt:
        # Catches Ctrl+C so the program exits cleanly.
        vprint(2, "\n[!] Scan interrupted by user. Exiting.")
        sys.exit(0)
        # Exits normally (exit code 0)
    
    except Exception as e:
        vprint(2, f"[!] Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    # ensures main() only runs when the script is executed directly.
    # not when imported as a module. 
    main()
