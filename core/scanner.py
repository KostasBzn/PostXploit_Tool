from core.colors import Colors as cl
import netifaces
from scapy.all import ARP, Ether, srp, ICMP, IP, sr1
import ipaddress
import socket
import re

def get_network_info():
    interfaces = netifaces.interfaces()
    for iface in interfaces:
        if iface == 'lo': 
            continue
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addrs:
            interface = iface
            ip = addrs[netifaces.AF_INET][0]['addr']
            netmask = addrs[netifaces.AF_INET][0]['netmask']
            gateway = netifaces.gateways()['default'][netifaces.AF_INET][0]
            return interface, ip, netmask, gateway
    print(f"{cl.yellow}[*] No active network interfaces found.{cl.reset}")

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

def compiled_scan():
    # Step 1: Get network info
    print(f"\n{cl.cyan}[~] Gathering network information...{cl.reset}")
    interface, ip, netmask, gateway = get_network_info()
    if not ip:
        return
    
    print(f"{cl.green}[+] Found network info:{cl.reset}")
    print(f"  {cl.teal}- Interface:{cl.reset} {interface}")
    print(f"  {cl.teal}- IP Address:{cl.reset} {ip}")
    print(f"  {cl.teal}- Netmask:{cl.reset} {netmask}")
    print(f"  {cl.teal}- Gateway:{cl.reset} {gateway}")
    
    # Step 2: ARP scan
    hosts = arp_scan()
    
    if not hosts:
        print(f"{cl.yellow}[!] No live hosts found.{cl.reset}")
        return
    
    print(f"{cl.green}[+] Found {len(hosts)} live host(s):{cl.reset}")
    for i, host in enumerate(hosts, 1):
        print(f"  {cl.purple}{i}.{cl.reset} {cl.teal}IP:{cl.reset} {host['ip']}\t  {cl.teal}MAC:{cl.reset} {host['mac']}")
    
    # Step 3: Port scanning
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

    print(f"{cl.cyan}[*] Scanning ports {port_min}-{port_max}...{cl.reset}")

    for host in hosts:
        print(f"\n{cl.yellow}[*] Scanning {host['ip']}...{cl.reset}")
        open_ports = port_scan(host['ip'], port_min, port_max)
        
        if open_ports:
            print(f"{cl.green}[+] Open ports on {host['ip']}:{cl.reset} {', '.join(map(str, open_ports))}\n")
        else:
            print(f"{cl.yellow}[!] No open ports found on {host['ip']}{cl.reset}")
    pass