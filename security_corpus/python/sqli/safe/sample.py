import sqlite3


def get_user_safe(username: str):
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    # Parameterized query is safe
    cursor.execute("SELECT * FROM users WHERE name = ?", (username,))
    return cursor.fetchall()
