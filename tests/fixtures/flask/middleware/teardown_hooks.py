from flask import Flask

app = Flask(__name__)

@app.teardown_request
def teardown_req(exception=None):
    print("Cleaning up request resource...")

@app.teardown_appcontext
def teardown_ctx(exception=None):
    print("Cleaning up app context DB session...")
