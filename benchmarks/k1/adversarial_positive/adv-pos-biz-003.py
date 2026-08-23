def edit_user_profile(req, user):
    # Vertical IDOR
    user.role = req.json.get("role")
    db.commit()
