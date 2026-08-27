def fetch_account_details(account_id, current_user_id):
    db_query = "SELECT * FROM accounts WHERE id=? AND owner_id=?"
    return execute_db(db_query, (account_id, current_user_id))

def execute_db(q, params):
    return {"id": 101, "balance": 5000}
