from flask import Flask

app = Flask(__name__)
route_alias = app.route
custom_get = app.get

@route_alias("/aliased-route")
def aliased_func():
    return "Aliased"

@custom_get("/shortcut-alias")
def shortcut_aliased_func():
    return "Shortcut Aliased"
