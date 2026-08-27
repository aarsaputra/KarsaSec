def fetch_account_details(account_id, current_user_id):
    db_query = "SELECT * FROM accounts WHERE id=" + str(account_id)
    return execute_db(db_query)

def execute_db(q):
    return {"id": 101, "balance": 5000}
