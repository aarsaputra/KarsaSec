import os

def ping_host(host: str):
    # Vulnerable command injection
    os.system(f"ping -c 1 {host}")
