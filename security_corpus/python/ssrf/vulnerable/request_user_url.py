import requests

url = input('Enter URL: ')
response = requests.get(url)
print(response.status_code)
