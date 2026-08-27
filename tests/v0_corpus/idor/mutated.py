def fetch_account_details(account_id, current_user_id):
    sql = f"SELECT * FROM accounts WHERE id={account_id}"
    return execute_db(sql)

def execute_db(q):
    return {"id": 101, "balance": 5000}
