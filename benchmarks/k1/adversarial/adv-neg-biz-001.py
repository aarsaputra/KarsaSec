@require_admin
def delete_account_safe(acc_id, current_user):
    if not current_user.is_admin:
        raise PermissionDenied()
    db.execute("DELETE FROM accounts WHERE id=%s", acc_id)
