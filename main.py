from core.colors import Colors as cl
from core.help import help_menu
from core.scanner import compiled_scan
import os
from datetime import datetime

def banner():
    if os.name == "nt":
        os.system("cls")
    else:
        os.system("clear")
    logo = cl.purple + r"""
#############################################

______         _  __   __      _       _ _   
| ___ \       | | \ \ / /     | |     (_) |  
| |_/ /__  ___| |_ \ V / _ __ | | ___  _| |_ 
|  __/ _ \/ __| __|/   \| '_ \| |/ _ \| | __|
| | | (_) \__ \ |_/ /^\ \ |_) | | (_) | | |_ 
\_|  \___/|___/\__\/   \/ .__/|_|\___/|_|\__|
                        | |                  
                        |_|                  

#############################################                     
""" + cl.reset + "\n"
    print(logo)
    #print(f"{cl.cyan}[~] Started at > [{datetime.now().strftime("%H:%M:%S")}]{cl.reset}")
    print(f"{cl.yellow}[$] Type 'help' for the available commands.{cl.reset}\n\n")

def check_sudo():
    """Verify sudo privileges."""
    if not "SUDO_UID" in os.environ.keys():
        print(f"{cl.red}[!] Please run the tool with sudo privileges.{cl.reset}")
        exit()

def command_handler(cmd):
    try:
        if not cmd:
            raise ValueError("Invalid command. Type 'help' for the available commands.")
        
        cmd = cmd.strip().lower()

        if cmd == "help":
            help_menu()

        elif cmd == "exit":
            print(f"{cl.yellow}[*] Exiting...{cl.reset}")
            exit()

        elif cmd == "net-scan":
            compiled_scan()
    
        elif cmd == "enum_services":
            print(f"{cl.cyan}[~] Enumerating services like SMB, SSH, RDP...{cl.reset}")

        elif cmd == "enum_users":
            print(f"{cl.cyan}[~] Extracting user info from open shares or SMB responses...{cl.reset}")

        elif cmd == "exploit_smb":
            print(f"{cl.cyan}[~] Attempting SMB vulnerability exploitation...{cl.reset}")

        elif cmd == "brute_ssh":
            print(f"{cl.cyan}[~] Starting SSH brute-force with credentials list...{cl.reset}")

        elif cmd == "dump_creds":
            print(f"{cl.cyan}[~] Dumping credentials from target system...{cl.reset}")

        elif cmd == "lateral_move":
            print(f"{cl.cyan}[~] Trying lateral movement using captured credentials...{cl.reset}")

        elif cmd == "persistence":
            print(f"{cl.cyan}[~] Establishing persistence on compromised host...{cl.reset}")

        elif cmd == "status":
            print(f"{cl.cyan}[~] Displaying current session and host status...{cl.reset}")

        elif cmd == "clear":
            banner()

        else:
            print(f"{cl.yellow}[*] Unknown command. Type 'help' for the available commands.{cl.reset}")
    
    except ValueError as e:
        print(f"\n{cl.red}[!] Input error: {e}{cl.reset}")


def main():
    try:
        check_sudo()
        banner()
        while True:
            cmd = input(f"{cl.blue}>>> {cl.reset}").lower()
            command_handler(cmd)

    except KeyboardInterrupt:
        print(f"{cl.yellow} [*] Interrupted by user, exiting...{cl.reset}")
        exit()
    except (Exception) as e:
        print(f"{cl.red}[!] Error: {e}{cl.reset}")
        exit()


if __name__ == "__main__":
    main()
