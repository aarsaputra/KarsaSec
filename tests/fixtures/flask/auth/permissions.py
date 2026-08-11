from flask import Flask

app = Flask(__name__)

def permission_required(perm):
    def decorator(fn):
        return fn
    return decorator

@app.route("/write")
@permission_required("users.write")
def write_user():
    return "Written"
