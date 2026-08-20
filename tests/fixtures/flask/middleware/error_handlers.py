from flask import Flask

app = Flask(__name__)


@app.errorhandler(404)
def not_found_error(error):
    return "Not Found", 404


@app.errorhandler(500)
def internal_error(error):
    return "Server Error", 500


@app.errorhandler(ValueError)
def handle_value_error(error):
    return "Bad Value", 400


@app.errorhandler(Exception)
def handle_generic_exception(error):
    return "Unhandled Exception", 500
