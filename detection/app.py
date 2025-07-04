# app.py
from flask import Flask
app = Flask(__name__)

@app.route("/")
def home():
    return "Github -> Jenkins -> Docker 이미지 빌드 -> Docker 컨테이너 실행 -> Discord Notification"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
