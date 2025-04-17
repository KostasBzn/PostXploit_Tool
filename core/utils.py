from core.colors import Colors as cl
from scapy.all import ARP, Ether, srp
import ipaddress
import socket
import re

def arp_scan():
    while True:
        ip_range = input(f"\n{cl.blue}[>] Enter IP range to scan (e.g., 192.168.0.0/24): {cl.reset}").strip()
        try:
            ipaddress.ip_network(ip_range, strict=False)
            break
        except ValueError:
            print(f"{cl.red}[!] Invalid IP range format.{cl.reset}")
    
    hosts = list()
    print(f"\n{cl.cyan}[~] Discovering live hosts...{cl.reset}")
    try:
        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        result = srp(ether/arp, timeout=3, verbose=0)[0]
        for sent, received in result:
            hosts.append({'ip': received.psrc, 'mac': received.hwsrc})
        return hosts
    except Exception as e:
        print(f"{cl.red}[!] ARP scan failed: {e}{cl.reset}")
        return []
    
def port_scan(ip, port_min, port_max):
    open_ports = []
    for port in range(port_min, port_max + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            if sock.connect_ex((ip, port)) == 0:
                open_ports.append(port)
    return open_ports

def port_range():
        port_range_pattern = re.compile("([0-9]+)-([0-9]+)")
        port_min, port_max = 0, 65535
        while True:
            port_range = input(f"\n{cl.blue}[>] Enter port range (e.g., 20-80 | leave empty for all ports): {cl.reset}").strip()
            if not port_range:
                break
            port_range_valid = port_range_pattern.search(port_range.replace(" ",""))
            if port_range_valid and 0 <= port_min <= port_max <= 65535:
                port_min = int(port_range_valid.group(1))
                port_max = int(port_range_valid.group(2))
                if 0 <= port_min <= port_max <= 65535:
                   break
            else:
                print(f"{cl.red}[!] Invalid port range. Use format 'min-max' (0-65535){cl.reset}")
        return port_min, port_max