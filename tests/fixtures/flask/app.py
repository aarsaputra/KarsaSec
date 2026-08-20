from flask import Flask, render_template, request

app = Flask(__name__)
app.config["SECRET_KEY"] = "dev-secret-key"


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    return render_template("index.html", user=username)


if __name__ == "__main__":
    app.run()
