from flask import Flask
from flask.views import View

app = Flask(__name__)


class ListView(View):
    methods = ["GET", "POST"]

    def dispatch_request(self):
        return "List items"
