import requests

allowed_hosts = ['example.com']

url = input('Enter URL: ')
if 'example.com' in url:
    response = requests.get(url)
    print(response.status_code)
