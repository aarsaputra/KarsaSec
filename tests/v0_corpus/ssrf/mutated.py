import urllib.request

def fetch_url(target_url):
    endpoint = f"http://{target_url}/api"
    req = urllib.request.urlopen(endpoint)
    return req.read()
