from flask import Flask
from flask_caching import Cache
from flask_cors import CORS
from flask_limiter import Limiter
from flask_login import LoginManager

app = Flask(__name__)

cors = CORS(app)
limiter = Limiter(app)
login_manager = LoginManager(app)
cache = Cache(app)
