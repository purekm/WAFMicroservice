# app.py
from flask import Flask
app = Flask(__name__)

@app.route("/")
def home():
    return "여기까지 진행해보았습니다 동수씨."

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
