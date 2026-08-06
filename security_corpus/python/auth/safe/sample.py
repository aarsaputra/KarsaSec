import os

import bcrypt
import jwt


def login_user(password):
    secret_key = os.environ.get("JWT_SECRET")
    token = jwt.encode({"user": "admin"}, key=secret_key)
    hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    return token, hashed_pw
