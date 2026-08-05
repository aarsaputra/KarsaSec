import os

def ping_host():
    # Vulnerable command injection from user input
    host = input('Enter host: ')
    os.system(f"ping -c 1 {host}")
