def delete_user(user_id):
    db.query("DELETE FROM users WHERE id = %s", user_id)
    return {"status": "deleted"}
