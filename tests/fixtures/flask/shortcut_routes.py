from flask import Flask

app = Flask(__name__)

@app.get("/items")
def get_items():
    return []

@app.post("/items")
def create_item():
    return {}

@app.put("/items/<int:item_id>")
def update_item(item_id):
    return {}

@app.delete("/items/<int:item_id>")
def delete_item(item_id):
    return {}
