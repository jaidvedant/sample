import socket
import ipaddress
import threading
from concurrent.futures import ThreadPoolExecutor

print_lock = threading.Lock()

def is_host_alive(ip):
    """Check if host is alive by attempting connections to common ports."""
    for port in [80, 443]:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((str(ip), port))
                if result == 0:
                    return True
        except:
            continue
    return False

def scan_port(ip, port):
    """Scan individual port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            with print_lock:
                if result == 0:
                    print(f"[+] {ip}:{port} is OPEN")
                else:
                    print(f"[-] {ip}:{port} is CLOSED")
    except:
        pass

def scan_host(ip, ports):
    """Scan ports on a live host."""
    if is_host_alive(ip):
        print(f"\n[+] Host {ip} is ALIVE. Scanning ports...")
        for port in ports:
            scan_port(str(ip), port)
    else:
        print(f"[-] Host {ip} is NOT responding.")

def main():
    try:
        # Get IP range input from the user
        user_input = input("Enter IP range (e.g., 192.168.1.0/30): ")
        network = ipaddress.IPv4Network(user_input, strict=False)
    except ValueError:
        print("Invalid IP range format. Example: 192.168.1.0/24")
        return

    # Define ports to scan
    ports_to_scan = [22, 23, 25, 53, 80, 110, 139, 443, 445, 3389]

    print("\nStarting network and port scan...\n")

    with ThreadPoolExecutor(max_workers=50) as executor:
        for ip in network.hosts():
            executor.submit(scan_host, ip, ports_to_scan)

if __name__ == "__main__":
    main()
