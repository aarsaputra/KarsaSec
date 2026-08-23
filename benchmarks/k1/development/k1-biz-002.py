@require_admin
def delete_user_safe(user_id, current_user):
    if not current_user.is_admin:
        raise PermissionDenied()
    db.query("DELETE FROM users WHERE id = %s", user_id)
