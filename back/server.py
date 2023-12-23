from flask import Flask, render_template, url_for
from flask_cors import CORS, cross_origin
from flask import request, jsonify
import sqlite3
from waitress import serve
from flask_jwt_extended import get_jwt_identity, jwt_required, JWTManager, create_access_token, set_access_cookies

# config =  json.load(open("./config.json", "r"))
app = Flask(__name__, )

app.config["JWT_SECRET_KEY"] = "secret"
jwt = JWTManager(app)

CORS(app, supports_credentials=True)
@app.get("/api/<id>")
def index(id):
    # print(id)
    return id

@app.post("/api/login")
def login():
    json_data = request.get_json()
    print(json_data)
    at = create_access_token(identity=json_data["email"])
    response = jsonify({"data": "login successful"})
    set_access_cookies(response, at)
    return response

@app.get("/api/jwt")
@jwt_required(locations=["cookies"])
def protected():
    print("a")
    cu = get_jwt_identity()
    response = jsonify(logged_in_as=cu)

    return response, 200

if __name__ == "__main__":
    serve(app, host="0.0.0.0", port=8080, url_scheme="https")

    # con = sqlite3.connect("tutorial.db")
    # cur = con.cursor()
    # cur.execute("CREATE TABLE movie(title, year, score)")
    # cur.execute("INSERT into movie values ('a', 'b', 'c')")
    # return app
