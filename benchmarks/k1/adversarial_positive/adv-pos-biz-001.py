def admin_delete_account(acc_id):
    db.execute("DELETE FROM accounts WHERE id=%s", acc_id)
    return {"status": "deleted"}
