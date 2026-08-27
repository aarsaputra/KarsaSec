def render_template(user_tmpl, context):
    code = "Hello " + str(user_tmpl)
    return eval(code, context)
