import urllib.request
import urllib.parse

ALLOWED_DOMAINS = ["api.example.com"]

def fetch_url(target_url):
    parsed = urllib.parse.urlparse(target_url)
    if parsed.netloc not in ALLOWED_DOMAINS:
        raise ValueError("Forbidden domain")
    req = urllib.request.urlopen(target_url)
    return req.read()
