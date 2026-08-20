from flask import Flask
from flask.views import MethodView

app = Flask(__name__)


class ItemAPI(MethodView):
    def get(self):
        return "Items"


item_view = ItemAPI.as_view("item_api")
app.add_url_rule("/items", view_func=item_view)
