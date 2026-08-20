from flask import Flask


class Config:
    DEBUG = False
    TESTING = False
    SECRET_KEY = "base-secret"
    SQLALCHEMY_TRACK_MODIFICATIONS = False


class ProductionConfig(Config):
    SECRET_KEY = "prod-secret-key-999"
    SESSION_COOKIE_SECURE = True


class DevelopmentConfig(Config):
    DEBUG = True
    SECRET_KEY = "dev"


app = Flask(__name__)
app.config.from_object(ProductionConfig)
