from flask import Flask
from flask.views import MethodView

app = Flask(__name__)

class UserAPI(MethodView):

    def get(self, user_id: int):
        return f"User {user_id}"

    def post(self):
        return "Created"

    def delete(self, user_id: int):
        return "Deleted"
