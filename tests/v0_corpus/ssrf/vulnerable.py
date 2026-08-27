import urllib.request

def fetch_url(target_url):
    req = urllib.request.urlopen(target_url)
    return req.read()
