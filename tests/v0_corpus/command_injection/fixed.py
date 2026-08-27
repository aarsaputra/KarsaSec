import subprocess

def ping_host(user_host):
    subprocess.run(["ping", "-c", "1", user_host], check=True)
