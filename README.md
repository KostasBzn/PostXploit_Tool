# Plan

## ✅ 1. Setup - done
- [x] Set up virtual environment
- [x] Install required Python packages:
  - impacket
  - scapy
  - paramiko
  - netifaces

## ✅ 2. Basic Network Scanning - done
- [x] Get local IP address, subnet mask, and gateway
- [x] Discover live hosts (ARP or ping sweep)
- [x] Scan for open ports on discovered hosts

## ✅ 3. Service Enumeration - done
- [x] Identify OS (via banner grabbing, TTL, etc.)
- [x] Detect services (SMB, RDP, SSH, HTTP, etc.)
- [x] Enumerate SMB shares and users

## ✅ 4. Exploitation - done
- [x] Attempt anonymous/null SMB login
- [x] Brute-force SMB or SSH login with wordlist
- [x] Scan for known vulnerabilities (e.g. EternalBlue)

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
- [x] Build a simple CLI menu or web dashboard
- [ ] Track compromised hosts and their status
- [ ] Log actions and outputs for each host
