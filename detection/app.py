# app.py
from flask import Flask
app = Flask(__name__)

@app.route("/")
def home():
    return "Github -> Jenkins -> Docker 정말로 된건가요!? 진짜 마지막 테스트!!"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
