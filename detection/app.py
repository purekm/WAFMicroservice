# app.py
from flask import Flask
app = Flask(__name__)

@app.route("/")
def home():
    return "Github -> Jenkins -> Docker 이제 진짜 진짜 진짜 진짜 연동 되었나요?!"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
