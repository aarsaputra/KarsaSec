import hashlib

password = input('Enter password: ')
hashed = hashlib.md5(password.encode('utf-8')).hexdigest()
print(hashed)
