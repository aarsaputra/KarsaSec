def render_template(user_tmpl, context):
    compiled = f"Hello {user_tmpl}"
    return eval(compiled, context)
