import socket
# Imports Python's low-level networking module.
# This lets us create TCP sockets, resolve hostnames, and connect to ports.

import sys
# Imports system-specific functions.
# We use this mainly for sys.exit() to cleanly terminate the program.

from concurrent.futures import ThreadPoolExecutor, as_completed
# Imports tools for running functions concurrently (multi-threading).
# ThreadPoolExecutor manages worker threads.
# as_completed lets us process results at threads finish.

def resolve_host(hostname):
	# Defines a function that converts a hostname (e.g., scanme.nmap.org)
	# into an IP address.

	try:
		# Attempt to resolve the hostname using DNS
		return socket.gethostbyname(hostname)
	except socket.gaierror as e:
		# Catches DNS-related errors (e.g., invalid hostnames, DNS failure).
		print(f"[!] Hostname resolution failed for {hostname}: {e}")
		# Prints an error message explaining what went wrong.
		sys.exit(1)
		# Exits the program with a non-zero exit code (indicates failure).

def scan_port(ip, port):
	# Defines a function that checks whether a specific TCP port is open
	# on a given IP address.

	try:
		# Creates a TCP socket using IPv4 (AF_INET) and TCP (SOCK_STREAM).
		# The 'with' statement ensures the socket is closed automatically.
		with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:

			#Sets a timeout of 1 second so we don't hang on slow ports.
			s.settimeout(1)

			# Attempts to connect to the IP and port.
			# connect_ex() returns 0 on success, non-zero on failure.
			if s.connect_ex((ip, port)) == 0:
				# If the port is open, return the port number.
				return port

			# If the port is closed, return None.
			return None

	except socket.error as e:
		# Catches lower-level socket errors (network issues, resets, etc.).
		print(f"[!] Socket error on port {port}: {e}")
		# Returns False of indicate the scan failedfor this port.
		return False

def main():
	# Main function - this is where program execution starts.

	hostname = "scanme.nmap.org"
	# Defines the target hostname to scan.

	ip = resolve_host(hostname)
	# Resolves the hostname into an IP address.

	print(f"[*] Scanning {hostname} ({ip})")
	# Prints status information so the user knows what's being scanned.

	try:
		# Creates a pool of up to 100 worker threads.
		with ThreadPoolExecutor(max_workers=100) as executor:

			# Submits scan_port() tasks to the thread pool for ports 1-1024.
			# Each call runs in a separate thread.
			futures = [executor.submit(scan_port, ip, port) for port in range(1, 1025)]
			
			# Iterates over futures as they finish (not in order).
			for future in as_completed(futures):

				# Retrieves the return value from scan_port().
				port = future.result()

				# If a port number was returned, the port is open.
				if port:
					print(f"[+] Port {port} open")

	except KeyboardInterrupt:
		# Catches Ctrl+C so the program exits cleanly.
		print("\n[!] Scan interrupted by user. Exiting.")
		sys.exit(0)
		# Exits normally (exit code 0)

	print("[*] Scan complete.")
	# Indicates the scan finished successfully.

if __name__ == "__main__":
	# ensures main() only runs when the script is executed directly.
	# not when imported as a module. 
	main()
