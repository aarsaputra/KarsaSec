@require_admin
def delete_account_admin_decorator_guarded(acc_id):
    db.execute("DELETE FROM accounts WHERE id=%s", acc_id)
    return {"status": "deleted"}
