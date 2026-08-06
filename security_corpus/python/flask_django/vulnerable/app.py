from flask import Flask

app = Flask(__name__)
app.config['SECRET_KEY'] = 'hardcoded_super_secret_key_123'

@app.route('/')
def index():
    return "Hello"

if __name__ == '__main__':
    app.run(debug=True)
