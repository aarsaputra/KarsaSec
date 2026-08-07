from basic_app.app import app


@app.route("/about")
def about():
    return "About Us"
