#!/usr/bin/env python3
"""Color constants for Z3NHAWK"""

from colorama import init, Fore, Style

init(autoreset=True)

class Colors:
    HEADER = Fore.CYAN
    OKBLUE = Fore.BLUE
    OKGREEN = Fore.GREEN
    WARNING = Fore.YELLOW
    FAIL = Fore.RED
    ENDC = Style.RESET_ALL
    BOLD = Style.BRIGHT