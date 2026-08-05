import hashlib

password = 'secret'
hashed = hashlib.md5(password.encode('utf-8')).hexdigest()
print(hashed)
