class Colors():
    light_green = "\033[38;5;120m"  # For highlighting important values (e.g., credentials, key info)
    cyan        = "\033[0;36m"      # For general info/status updates (e.g., "Scanning...", "Waiting...")
    red         = "\033[1;31m"      # For errors or failures (e.g., "Access denied", "Connection failed")
    green       = "\033[38;5;82m"   # For success messages (e.g., "Login successful", "Exploit succeeded")
    yellow      = "\033[1;33m"      # For warnings or alerts (e.g., "Suspicious response", "High risk")
    blue        = "\033[1;34m"      # For commands being executed or shown (e.g., "Running: nmap -sS ...")
    purple      = "\033[1;35m"      # For banners, headers, and tool titles
    teal        = "\033[38;5;37m"   # For discoveries or findings (e.g., open ports, new hosts)
    reset       = "\033[0m"      
