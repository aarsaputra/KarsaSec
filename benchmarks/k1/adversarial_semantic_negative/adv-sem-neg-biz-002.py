def update_role_super_admin_guarded(req, user, current_user):
    new_role = req.json.get("role")
    if not current_user.is_super_admin:
        raise PermissionDenied("Super admin access required")
    user.role = new_role
    db.commit()
