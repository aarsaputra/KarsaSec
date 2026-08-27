import html

def render_profile(user_input):
    safe_input = html.escape(user_input)
    output = "<div>User: " + safe_input + "</div>"
    print(output)
    return output
