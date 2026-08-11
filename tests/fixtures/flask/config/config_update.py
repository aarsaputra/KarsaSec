from flask import Flask

app = Flask(__name__)
app.config.update(
    DEBUG=False,
    SECRET_KEY="update-secret-key",
    WTF_CSRF_ENABLED=True,
)
app.config.from_mapping(
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,
    TEMPLATES_AUTO_RELOAD=False,
)
