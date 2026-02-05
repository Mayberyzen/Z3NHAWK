#!/usr/bin/env python3
"""Banner display module"""

from utils.colors import Colors

def show():
    """Display Z3NHAWK banner"""
    banner = f"""
{Colors.HEADER}{Colors.BOLD}
███████╗██████╗ ███╗   ██╗██╗  ██╗ █████╗ ██╗    ██╗██╗  ██╗
╚══███╔╝╚════██╗████╗  ██║██║  ██║██╔══██╗██║    ██║██║ ██╔╝
  ███╔╝  █████╔╝██╔██╗ ██║███████║███████║██║ █╗ ██║█████╔╝ 
 ███╔╝  ██╔═══╝ ██║╚██╗██║██╔══██║██╔══██║██║███╗██║██╔═██╗ 
███████╗███████╗██║ ╚████║██║  ██║██║  ██║╚███╔███╔╝██║  ██╗
╚══════╝╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝
{Colors.ENDC}
{Colors.OKGREEN}[+] Modular OSINT Framework v3.0{Colors.ENDC}
{Colors.OKBLUE}[+] Separate modules for each reconnaissance type{Colors.ENDC}
    """
    print(banner)