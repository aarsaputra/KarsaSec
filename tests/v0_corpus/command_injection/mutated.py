import os

def ping_host(user_host):
    os.system(f"ping -c 1 {user_host}")
