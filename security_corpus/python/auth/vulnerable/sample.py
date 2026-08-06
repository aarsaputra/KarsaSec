import jwt
import hashlib

def login_user(password):
    token = jwt.encode({"user": "admin"}, key="super_secret_jwt_key_123")
    hashed_pw = hashlib.md5(password.encode()).hexdigest()
    return token, hashed_pw
