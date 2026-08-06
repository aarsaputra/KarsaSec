import sqlite3


def get_user_regression():
    user_id = input('Enter user id: ')
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    sql = "SELECT id, name FROM users WHERE id = " + str(user_id)
    cursor.execute(sql)
    return cursor.fetchone()
