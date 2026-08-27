import os

def ping_host(user_host):
    cmd = "ping -c 1 " + user_host
    os.system(cmd)
