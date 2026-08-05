import hashlib

password = 'secret'
hashed = hashlib.sha256(password.encode('utf-8')).hexdigest()
print(hashed)
