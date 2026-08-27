def render_template(user_tmpl, context):
    return f"Hello {context.get('name', '')}"
