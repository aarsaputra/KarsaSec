def update_profile_safe(req, user, current_user):
    user.name = req.json.get("name")
    if current_user.is_super_admin and "role" in req.json:
        user.role = req.json["role"]
    db.commit()
