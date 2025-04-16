PostXploit/
├── core/
│   ├── scanner.py           # Network scanning functions
│   ├── enumerator.py        # Service & host info gathering
│   ├── exploit_smb.py       # SMB enumeration + attack scripts
│   ├── lateral_move.py      # Lateral movement mechanisms
│   ├── persistence.py       # Persistence mechanisms (optional)
│   ├── creds.py             # Credential dumping tools
├── utils/
│   ├── helpers.py           # Shared utility functions
│   ├── config.py            # Configuration, IP ranges, credentials
├── main.py                  # Entry point / CLI interface
├── requirements.txt         # Dependencies (e.g., impacket, paramiko)
└── README.md


# 🛠️ Internal Network Enumeration & Exploitation Tool - To-Do Plan

# PostXploit

## ✅ 1. Setup
- [ ] Set up virtual environment
- [ ] Install required Python packages:
  - impacket
  - scapy
  - paramiko
  - netifaces
  - flask (optional, for web GUI)

## ✅ 2. Basic Network Scanning
- [ ] Get local IP address, subnet mask, and gateway
- [ ] Discover live hosts (ARP or ping sweep)
- [ ] Scan for open ports on discovered hosts

## ✅ 3. Service Enumeration
- [ ] Identify OS (via banner grabbing, TTL, etc.)
- [ ] Detect services (SMB, RDP, SSH, HTTP, etc.)
- [ ] Enumerate SMB shares and users

## ✅ 4. Exploitation
- [ ] Attempt anonymous/null SMB login
- [ ] Brute-force SMB or SSH login with wordlist
- [ ] Scan for known vulnerabilities (e.g. EternalBlue)

## ✅ 5. Credential Dumping
- [ ] Use impacket tools (secretsdump, samrdump)
- [ ] Interface with mimikatz on a Windows target

## ✅ 6. Lateral Movement
- [ ] Use stolen credentials to move to other hosts
- [ ] Transfer and execute payloads via SMB, SSH, etc.

## ✅ 7. Persistence (Optional)
- [ ] Add scheduled task on Windows
- [ ] Modify registry (run keys)
- [ ] Maintain reverse shell with autorun

## ✅ 8. Command & Control Interface
- [ ] Build a simple CLI menu or web dashboard
- [ ] Track compromised hosts and their status
- [ ] Log actions and outputs for each host
