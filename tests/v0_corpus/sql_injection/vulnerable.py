import sqlite3

def get_user_data(user_id):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id=" + user_id
    cursor.execute(query)
    return cursor.fetchall()
