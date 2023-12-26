from flask import Flask 
from flask_cors import CORS
from flask import request, jsonify, redirect
import sqlite3
from waitress import serve
from flask_jwt_extended import get_jwt_identity, jwt_required, JWTManager, create_access_token, set_access_cookies, get_jwt
from datetime import timedelta
from password_strength import PasswordPolicy
import time
import bcrypt

# config =  json.load(open("./config.json", "r"))
app = Flask(__name__)
CORS(app, supports_credentials=True, origins=["http://localhost*", "https://localhost*"])

app.config["JWT_SECRET_KEY"] = "secret1"
app.config["JWT_COOKIE_SECURE"] = True
app.config["JWT_COOKIE_SAMESITE"] = "Strict"
# app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(seconds=5)
jwt = JWTManager(app)

def make_db_call(**kwargs):
    db = sqlite3.connect("jwt_blacklist_db")
    dbcur = db.cursor()
    result = None

    if kwargs.get("one") is not None:
        arguments = kwargs.get("args", ())
        result = dbcur.execute(kwargs.get("one"), arguments)
    elif kwargs.get("many") is not None:
        arguments = kwargs.get("args", [])
        result = dbcur.executemany(kwargs.get("many"), arguments)
    if kwargs.get("fetchone") is not None:
        result = result.fetchone()
    elif kwargs.get("fetchall") is not None:
        result = result.fetchall()
    db.commit()
    db.close()
    return result
    
@jwt.token_in_blocklist_loader
def abc(jwt_header, jwt_payload):
    try:
        jti = jwt_payload["jti"]
        res = make_db_call(one="SELECT jti FROM revoked_jwt WHERE jti=?", args=(jti,), fetchone=1)
        return res is not None
    except Exception as e:
        print(e)
        return True

def server_response(message, result, code):
    return jsonify({"message": message, "result": result}), code

@app.post("/api/login")
def login():
    try:
        # time.sleep(2.0)
        json_data = request.get_json()
        email = json_data["email"]
        password = json_data["password"]
        user = make_db_call(one="SELECT * FROM users WHERE email == ?", args=(email,), fetchone=1)
        if user is None:
            return server_response("Invalid username or password", False, 401)

        if bcrypt.checkpw(password.encode(), user[1].encode()) == False:
            return server_response("Invalid username or password", False, 401)

        response = server_response("Login successful", True, 200)
        response = jsonify({"message": 'Login successful', "result": True})
        set_access_cookies(response, create_access_token(identity=json_data["email"]))
        return response
    except Exception as e:
        print(e)
        return server_response("Internal Error", False, 500)

@app.get("/api/logout")
@jwt_required(locations=["cookies"])
def logout():
    cu = get_jwt()["jti"]
    dbcur.execute("INSERT INTO revoked_jwt VALUES (?)", (cu,))
    db.commit()
    
    return "OK", 200
    

@app.get("/api/jwt")
@jwt_required(locations=["cookies"])
def protected():
    print("a")
    cu = get_jwt_identity()
    response = jsonify(logged_in_as=cu)

    return response, 200

@app.post("/api/register")
def register_validate():
    try:
        time.sleep(0.2)
        json = request.get_json(silent=True)
        if json is None:
            raise Exception()

        email = json["email"]
        passwd = json["password"]
        passwdr = json["password_repeat"]

        if(len(email) == 0):
            return server_response("Email cannot be that short", False, 401)
        if(len(email) > 64):
            return server_response("Email cannot be that long", False, 401)
        if(email.find("@") == -1 or email.find(".") == -1):
            return server_response("Email must have valid format with '@' and '.'", False, 401)

        if(len(passwd) < 8):
            return server_response("Password cannot be that short", False, 401)
        if(len(passwd) > 16):
            return server_response("Password cannot be that long", False, 401)
        if(passwd != passwdr):
            return server_response("Passwords are not the same", False, 401)

        # res = make_db_call(one="SELECT * FROM users", args = (email,), fetchall=1)
        # print(res)
        email_already_exists = make_db_call(one="SELECT COUNT(*) FROM users WHERE email == ?", args = (email,), fetchone=1)[0] > 0
        if(email_already_exists):
            return server_response("Email already exists", False, 401)
        
        if(make_db_call(one="SELECT COUNT(*) FROM bruteforce_passwords WHERE password LIKE ?", args = (passwd,), fetchone=1)[0] > 0):
            return server_response("Your password is compromised. Please, provide another one.", False, 401)
        
        policy = PasswordPolicy.from_names(strength=(0.66, 7))
        if len(policy.test(password=passwd)) != 0:
            return server_response("Your password is too weak. Please, consider adding uppercase letters, special characters and numbers.", False, 401)

        make_db_call(one="INSERT INTO users VALUES(?,?)", args=(email, bcrypt.hashpw(passwd.encode(), bcrypt.gensalt())))
        return server_response("Everything is good.", True, 200)
    except Exception as i:
        print(i)
        return {"message": "Internal Error", "result": False}, 500


if __name__ == "__main__":
    make_db_call(one = """
    CREATE TABLE IF NOT EXISTS revoked_jwt(jti)  
    """)

    # make_db_call(one = """
    # DROP TABLE IF EXISTS users
    # """)
    make_db_call(one = """
    CREATE TABLE IF NOT EXISTS users(
        email TEXT, 
        password TEXT
    )
    """)
    # make_db_call(one="INSERT INTO users VALUES(?,?)", args=("admin@admin.admin", bcrypt.hashpw("admin".encode(), bcrypt.gensalt()).decode()))

    # make_db_call(one = """
    # DROP TABLE IF EXISTS bruteforce_passwords
    # """)
    make_db_call(one = """
    CREATE TABLE IF NOT EXISTS bruteforce_passwords(
        password TEXT
    )
    """)

    # make_db_call(one = """
    # INSERT INTO users VALUES ('asdf@asdf.pl', 'asdf')
    # """)

    # file = open("passwords.txt", 'r')
    # passwords = [ (x,) for x in file.read().splitlines() ]
    # file.close()

    # make_db_call(many = """
    # INSERT INTO bruteforce_passwords VALUES(?)
    # """, args=passwords)

    serve(app, host="0.0.0.0", port=8080, url_scheme="https", threads=4)