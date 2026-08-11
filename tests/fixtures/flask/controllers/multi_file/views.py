from multi_file.app import app


@app.route("/dashboard")
def dashboard():
    return "Dashboard"
