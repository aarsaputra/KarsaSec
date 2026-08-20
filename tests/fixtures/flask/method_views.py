from flask import Flask
from flask.views import MethodView

app = Flask(__name__)


class UserAPI(MethodView):
    def get(self, user_id):
        return "User"

    def post(self):
        return "Created"

    def delete(self, user_id):
        return "Deleted"


user_view = UserAPI.as_view("user_api")
app.add_url_rule("/users/<int:user_id>", view_func=user_view, methods=["GET", "DELETE"])
app.add_url_rule("/users", view_func=user_view, methods=["POST"])
