"""
Network Enumerator Module

Performs deeper service enumeration with the command enum-services:
- OS detection via TTL and Nmap fingerprinting
- Open ports and services versions
- SMB share and user enumeration
- FTP service enumeration with anonymous login testing

Note:
Always ensure proper authorization before running network enumeration.
Some operations may trigger security alerts on monitored networks.
"""

from core.colors import Colors as cl
import socket
from scapy.all import IP, ICMP, sr1
import nmap
import re
import time
from ftplib import FTP
from core.utils import arp_scan, port_range
from core.help import what, yamete

def os_fingerprint(ip):
    """Identify OS via TTL and TCP/IP fingerprinting"""
    try:
        # TTL-based OS detection (TTL stands Time To Live)
        ping = sr1(IP(dst=ip)/ICMP(), timeout=2, verbose=0) # we ping the target to get the ttl, This is only an estimation
        if ping:
            ttl = ping.ttl
            if ttl <= 64:
                os_guess = "Linux/Unix"
            elif ttl <= 128:
                os_guess = "Windows"
            else:
                os_guess = "Unknown"

            # We get the OS fingerprinting via nmap
            nm = nmap.PortScanner()
            nm.scan(ip, arguments='-O') # -0 is the common nmap command for the OS detection
            os_info = nm[ip].get('osclass', [{}])[0].get('osfamily', os_guess)

            return f"{os_info} (TTL: {ttl})"
    except Exception as e:
        print(f"{cl.red}[!] OS detection failed: {e}{cl.reset}")
    return "Unknown"

def detect_services(ip, port_min, port_max):
    """Detect running services running on open ports"""
    services = {}
    nm = nmap.PortScanner()

    if port_min is None or port_max is None:
        nmap_range = "1-65535" 
    else:
        nmap_range = f"{port_min}-{port_max}"

    try:
        nm.scan(ip, ports=nmap_range, arguments='-sV --version-intensity 3') 
        # -sV the common nmap command to detect services versions
        # Intencity can be adjusted (0-9). Higher means slower/more accuracy, lowwer the oposite.
        for proto in nm[ip].all_protocols(): # loops through all protocols like tcp, upd and so on
            for port in nm[ip][proto]:
                service = nm[ip][proto][port]['name']
                product = nm[ip][proto][port].get('product', '')
                version = nm[ip][proto][port].get('version', '')
                services[port] = f"{service} {product} {version}".strip()
    except Exception as e:
        print(f"{cl.red}[!] Service detection failed: {e}{cl.reset}")

    return services

def enum_smb(ip):
    """Enumerate SMB shared folders and users"""
    results = {'shares': [], 'users': []}

    try:
        # we check if SMB port is open (SMB stands for Server Message Block)
        # if it is we list the shared folders(smb-enum-shares) and we list the users(smb-enum-users)

        # what we do here: we try to open a tcp connection on port 445, if it returns 0 it is open
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        if sock.connect_ex((ip, 445)) != 0:
            return None
        sock.close()

        # nmap SMB scripts
        nm = nmap.PortScanner()
        nm.scan(ip, arguments='--script smb-enum-shares,smb-enum-users -p 445') # nmap scripts(built in) they try to list the folders and the users

        scripts = nm[ip]['tcp'][445].get('script', {})

        # we use regex pattern to find the name/description
        if 'smb-enum-shares' in scripts:
            shares = re.findall(r"(\w+)\s+\w+\s+\w+\s+(.+)", scripts['smb-enum-shares'])
            results['shares'] = [{'name': s[0], 'path': s[1]} for s in shares]

        if 'smb-enum-users' in scripts:
            users = re.findall(r"\| (\S+)", scripts['smb-enum-users'])
            results['users'] = users

    except Exception as e:
        print(f"{cl.red}[!] SMB enumeration error: {e}{cl.reset}")

    return results if results['shares'] or results['users'] else None

def enum_ftp(ip):
    """Enumerate FTP service: attempt anonymous login and list files."""
    # Our goal here is to try anonymus login if the port 21 is open
    # FTP stands for File Transfer Protocol, typically it runs on port 21 and it is used to download, upload or browse files on a remote server.
    results = {
        'anonymous_login': False,
        'files': [],
        'banner': '' 
    }

    try:
        ftp = FTP()
        ftp.connect(ip, 21, timeout=3)
        time.sleep(1) # we add 1 sec delay to avoid detection
        banner = ftp.getwelcome() # we grab the banner. If it reveals the ftp version we can google for further exploits
        results['banner'] = banner.strip() if banner else "No banner"

        print(f"{cl.cyan}[~] FTP Banner:{cl.reset} {results['banner']}")

        # we try anonymous login
        ftp.login(user='anonymous', passwd='anonymous@domain.com')
        results['anonymous_login'] = True
        # some public/missconfigured ftps allow anonymous login
        # here comes the easter egg
        print(f"{cl.green}[+] Anonymous FTP login successful{cl.reset}")
        time.sleep(1)
        what()
        time.sleep(1)
        yamete()
        try:
            files = ftp.nlst()
            results['files'] = files
        except Exception:
            print(f"{cl.yellow}[!] Could not list directory contents{cl.reset}")
        
        ftp.quit()

    except Exception as e:
        print(f"{cl.red}[!] FTP enumeration error: {e}{cl.reset}")

    return results if results['anonymous_login'] else None

def service_enumeration():
    """Main enumeration function"""
    hosts = arp_scan()
    
    if not hosts:
        print(f"{cl.yellow}[!] No live hosts found.{cl.reset}")
        return
    
    print(f"{cl.green}[+] Found {len(hosts)} live host(s):{cl.reset}")
    for i, host in enumerate(hosts, 1):
        print(f"  {cl.purple}{i}.{cl.reset} {cl.teal}IP:{cl.reset} {host['ip']}\t  {cl.teal}MAC:{cl.reset} {host['mac']}")

    port_min, port_max = port_range()

    for host in hosts:
        ip = host['ip']
        print(f"\n{cl.cyan}[~] Enumerating {ip}{cl.reset}")

        # os detection
        os = os_fingerprint(ip)
        print(f"{cl.green}[+] OS Detection:{cl.reset} {os}")

        # service detection
        services = detect_services(ip, port_min, port_max)

        if services:
            print(f"{cl.green}[+] Services:{cl.reset}")
            for port, service in services.items():
                print(f"  {cl.teal}- Port {port}:{cl.reset} {service}")
                
                # ftp
                if port == 21 or 'ftp' in service.lower():
                    ftp_info = enum_ftp(ip)
                    if ftp_info:
                        print(f"    {cl.purple}FTP Anonymous Login:{cl.reset} {ftp_info['anonymous_login']}")
                        if ftp_info['files']:
                            print(f"    {cl.purple}FTP Files:{cl.reset}")
                            for file in ftp_info['files']:
                                print(f"      {file}")
                
                # SMB
                if port == 445 or 'microsoft-ds' in service.lower():
                    smb_info = enum_smb(ip)
                    if smb_info:
                        if smb_info['shares']:
                            print(f"    {cl.purple}SMB Shares:{cl.reset}")
                            for share in smb_info['shares']:
                                print(f"      {share['name']} -> {share['path']}")
                        if smb_info['users']:
                            print(f"    {cl.purple}SMB Users:{cl.reset} {', '.join(smb_info['users'])}")
        else:
            print(f"{cl.yellow}[!] No services detected{cl.reset}")
