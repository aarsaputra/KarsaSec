def render_profile(user_input):
    bad_sanitize = user_input.replace("<script>", "")
    html = f"<div>User: {bad_sanitize}</div>"
    print(html)
    return html
