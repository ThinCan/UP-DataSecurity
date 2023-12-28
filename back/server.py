from flask import Flask 
from flask_cors import CORS
from flask import request, jsonify, redirect
import sqlite3
from waitress import serve
from flask_jwt_extended import get_jwt_identity, jwt_required, JWTManager, create_access_token, set_access_cookies, get_jwt
from datetime import timedelta
from password_strength import PasswordPolicy
import time
import hashlib
import sss
import random
import dotenv
import os
import json

dotenv.load_dotenv()
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
def is_token_in_blocklist(jwt_header, jwt_payload):
    try:
        jti = jwt_payload["jti"]
        res = make_db_call(one="SELECT jti FROM revoked_jwt WHERE jti=?", args=(jti,), fetchone=1)
        return res is not None
    except Exception as e:
        print(e)
        return True

def server_response(message, result, code):
    return jsonify({"message": message, "result": result}), code

@app.post("/api/login/password_indices")
def login_password_indices():
    try:
        email = request.get_json()["email"]
        if len(email) == 0:
            return server_response("Email cannot be empty", False, 401)
        already_generated = make_db_call(one="SELECT i1,i2,i3,i4,i5 FROM user_password_indices WHERE email=?", args=(email,), fetchone=1)
        if already_generated is not None:
            already_generated = [x for x in already_generated]
            return server_response({"indices": already_generated}, True, 200)

        user = make_db_call(one="SELECT password FROM users WHERE email=?", args=(email,), fetchone=1)
        indices = random.sample(range(0, 16), 5)
        if user is not None:
            user = user[0]
            password_length = len(user) // 4 - 1
            indices = random.sample(range(0, password_length), 5)
        make_db_call(one="INSERT INTO user_password_indices VALUES (?, ?, ?, ?, ?, ?)", args=(email, *indices))
        return server_response({"indices": indices}, True, 200)

    except Exception as err:
        print(err)
        return server_response("Internal Error", False, 500) 


@app.post("/api/login")
def login():
    try:
        time.sleep(2.0)
        json_data = request.get_json()
        email = json_data["email"]
        password = json_data["password"]
        password.replace(' ', '')

        if len(email) < 0:
            return server_response("Invalid username or password", False, 401)
        if len(password) < 5:
            return server_response("Invalid username or password", False, 401)
        for l in password:
            if ord(l) > sss.MAX:
                return server_response("Invalid characters in password", False, 401)
        
        user = make_db_call(one="SELECT * FROM users WHERE email == ?", args=(email,), fetchone=1)
        if user is None:
            return server_response("Invalid username or password", False, 401)
        
        password_indices = make_db_call(one="SELECT i1,i2,i3,i4,i5 FROM user_password_indices WHERE email=?", args=(email,), fetchone=1)
        if password_indices is None:
            raise Exception()

        if len(password_indices) != len(password):
            return server_response("Fill every blank character inside password field", False, 401)
        
        y = user[1]
        z = []
        for i in range(0, len(y), 4):
            z.append(int.from_bytes(y[i:i+4]))
        y = z
        password = [(i, l.encode()) for i,l in zip(password_indices, [*password])]
        rec_secret = sss.reconstruct_secret(password, y)
        if rec_secret == y[-1]:
            make_db_call(one="DELETE FROM user_password_indices WHERE email=?", args=(email,))
            response = server_response("Login successful", True, 200)
            response = jsonify({"message": 'Login successful', "result": True})
            set_access_cookies(response, create_access_token(identity=email))
            return response
        return server_response("Incorrect login or password", False, 401)

    except Exception as e:
        print(e)
        return server_response("Internal Error", False, 500)

@app.get("/api/logout")
@jwt_required(locations=["cookies"])
def logout():
    try:
        cu = get_jwt()["jti"]
        make_db_call(one="INSERT INTO revoked_jwt VALUES (?)", args=(cu, ))
        return server_response("Successfully logged out", True, 200)
    except Exception as e:
        print(e)
        return server_response("Internal Error", False, 500)
    
@app.get("/api/jwt")
@jwt_required(locations=["cookies"])
def protected():
    return server_response("You are verified", True, 200)

@app.post("/api/register/validate")
def register_validate(*args):
    try:
        time.sleep(0.2)
        email = ""
        passwd = ""
        passwdr = ""

        if len(args) == 0:
            json = request.get_json()
            if json is None:
                raise Exception()
            email = json["email"]
            passwd = json["password"]
            passwdr = json["password_repeat"]
        elif len(args) == 3:
            email = args[0]
            passwd = args[1]
            passwdr = args[2]

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
        for l in passwd:
            if ord(l) > sss.MAX:
                return server_response("Password contains invalid characters", False, 401)
        if(passwd != passwdr):
            return server_response("Passwords are not the same", False, 401)

        email_already_exists = make_db_call(one="SELECT COUNT(*) FROM users WHERE email == ?", args = (email,), fetchone=1)[0] > 0
        if(email_already_exists):
            return server_response("Email already exists", False, 401)
        
        if(make_db_call(one="SELECT COUNT(*) FROM bruteforce_passwords WHERE password LIKE ?", args = (passwd,), fetchone=1)[0] > 0):
            return server_response("Your password is compromised. Please, provide another one.", False, 401)
        
        policy = PasswordPolicy.from_names(strength=(0.66, 7))
        if len(policy.test(password=passwd)) != 0:
            return server_response("Your password is too weak. Please, consider adding uppercase letters, special characters and numbers.", False, 401)

        return server_response("Everything is good.", True, 200)
    except Exception as i:
        print(i)
        return server_response("Internal Error", False, 500)

@app.post("/api/register")
def register():
    try:
        json = request.get_json(silent=True)
        if json is None:
            raise Exception()

        email = json["email"]
        passwd = json["password"]
        passwdr = json["password_repeat"]
        result = register_validate(email, passwd, passwdr)

        if result[1] == 200:
            secret = int.from_bytes(hashlib.sha256(passwd.encode()).digest()[:4])
            sh = sss.generate_shares(passwd.encode(), 5, secret)
            sh_str = b""
            for s in sh:
                sh_str += int.to_bytes(s, 4)
            sh_str += int.to_bytes(secret, 4)
            make_db_call(one="INSERT INTO users VALUES(?,?)", args=(email, sh_str))
        return result
    except Exception as err:
        print(err)
        return server_response("Internal Error", False, 500)

if __name__ == "__main__":
    make_db_call(one = """
    CREATE TABLE IF NOT EXISTS revoked_jwt(jti)  
    """)

    make_db_call(one = """
    DROP TABLE IF EXISTS users
    """)
    make_db_call(one = """
    CREATE TABLE IF NOT EXISTS users(
        email TEXT, 
        password TEXT
    )
    """)
    # make_db_call(one="INSERT INTO users VALUES(?,?)", args=("admin@admin.admin", bcrypt.hashpw("admin".encode(), bcrypt.gensalt()).decode()))

    make_db_call(one = """
    DROP TABLE IF EXISTS bruteforce_passwords
    """)
    make_db_call(one = """
    CREATE TABLE IF NOT EXISTS bruteforce_passwords(
        password TEXT
    )
    """)

    # make_db_call(one = """
    # DROP TABLE IF EXISTS user_password_indices
    # """)
    make_db_call(one = """
    CREATE TABLE IF NOT EXISTS user_password_indices(
        email TEXT,
        i1 INTEGER,
        i2 INTEGER,
        i3 INTEGER,
        i4 INTEGER,
        i5 INTEGER
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