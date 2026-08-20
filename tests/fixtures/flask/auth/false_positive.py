from flask import Flask, make_response, session

app = Flask(__name__)


def require_cache(fn):
    def wrapper(*args, **kwargs):
        return fn(*args, **kwargs)

    return wrapper


@app.route("/theme")
def set_theme():
    session["theme"] = "dark"
    session["language"] = "id"
    resp = make_response("Theme set")
    resp.set_cookie("theme", "dark")
    resp.set_cookie("banner_dismissed", "true")
    return resp


@app.route("/cached")
@require_cache
def cached_view():
    return "Cached content"
