"""
Network Scanner

Performs the network scanning with the command net-scan:
- Network interface detection (IP, netmask, gateway)
- ARP scanning for live host discovery
- TCP port scanning of discovered hosts
"""


from core.colors import Colors as cl
from core.utils import arp_scan, port_scan, port_range
import netifaces


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


def compiled_scan():
    # Get network info
    print(f"\n{cl.cyan}[~] Gathering network information...{cl.reset}")
    interface, ip, netmask, gateway = get_network_info()
    if not ip:
        return
    
    print(f"{cl.green}[+] Found network info:{cl.reset}")
    print(f"  {cl.teal}- Interface:{cl.reset} {interface}")
    print(f"  {cl.teal}- IP Address:{cl.reset} {ip}")
    print(f"  {cl.teal}- Netmask:{cl.reset} {netmask}")
    print(f"  {cl.teal}- Gateway:{cl.reset} {gateway}")
    
    # ARP scan
    hosts = arp_scan()
    
    if not hosts:
        print(f"{cl.yellow}[!] No live hosts found.{cl.reset}")
        return
    
    print(f"{cl.green}[+] Found {len(hosts)} live host(s):{cl.reset}")
    for i, host in enumerate(hosts, 1):
        print(f"  {cl.purple}{i}.{cl.reset} {cl.teal}IP:{cl.reset} {host['ip']}\t  {cl.teal}MAC:{cl.reset} {host['mac']}")
    
    # Port scanning
    port_min, port_max = port_range()
    print(f"\n{cl.cyan}[~] Scanning ports {port_min}-{port_max}...{cl.reset}")

    for host in hosts:
        print(f"{cl.yellow}[*] Scanning {host['ip']}...{cl.reset}")
        open_ports = port_scan(host['ip'], port_min, port_max)
        
        if open_ports:
            print(f"{cl.green}[+] Open ports on {host['ip']}:{cl.reset} {', '.join(map(str, open_ports))}\n")
        else:
            print(f"{cl.yellow}[!] No open ports found on {host['ip']}{cl.reset}\n")