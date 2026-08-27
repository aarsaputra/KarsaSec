import sqlite3

def get_user_data(user_id):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id=?"
    cursor.execute(query, (user_id,))
    return cursor.fetchall()
