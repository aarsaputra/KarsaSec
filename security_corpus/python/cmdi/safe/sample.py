import subprocess


def ping_host_safe(host: str):
    # Safe argument list without shell=True
    subprocess.run(["ping", "-c", "1", host], check=True)
