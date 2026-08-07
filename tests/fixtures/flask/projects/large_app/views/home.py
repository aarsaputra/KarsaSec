from large_app.app import app

@app.route("/dashboard")
def dashboard():
    return "Dashboard"
