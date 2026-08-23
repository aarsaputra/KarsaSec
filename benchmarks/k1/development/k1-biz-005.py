def update_profile(req, user):
    user.role = req.json.get("role")
    db.commit()
