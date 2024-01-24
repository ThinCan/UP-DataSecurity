from flask import Flask 
from flask_cors import CORS
from flask import request, jsonify
import sqlite3
from waitress import serve
from flask_jwt_extended import get_jwt_identity, jwt_required, JWTManager, create_access_token, set_access_cookies, get_jwt
from datetime import timedelta
from password_strength import PasswordPolicy
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import time
import hashlib
import sss
import random
import dotenv
import datetime
import os

dotenv.load_dotenv()
app = Flask(__name__)
CORS(app, supports_credentials=True, origins=["http://localhost*", "https://localhost*"])

app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET")
app.config["JWT_COOKIE_SECURE"] = True
app.config["JWT_COOKIE_SAMESITE"] = "Strict"
app.config["JWT_COOKIE_CSRF_PROTECT"] = False
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=2)
jwt = JWTManager(app)

def make_db_call(**kwargs):
    try:
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
    except Exception as err:
        db.close()
        print(err)
        return None
    
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
        email = request.get_json()["email"].lower()
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

def handle_timed_out_login(ip, was_current_login_ok): 
    try:
        make_db_call(one="DELETE FROM bad_logins WHERE last_time < ?", args=((datetime.datetime.now() - timedelta(minutes=5)).timestamp(), ))
        attempt = make_db_call(one="SELECT ip, last_time, tries FROM bad_logins WHERE ip = ?", args=(ip,), fetchone=1)
        now = datetime.datetime.now().timestamp()

        if attempt is None:
            make_db_call(one="INSERT INTO bad_logins(ip, last_time) VALUES(?, ?)", args=(ip, now))
            attempt = make_db_call(one="SELECT ip, last_time, tries FROM bad_logins WHERE ip = ?", args=(ip,), fetchone=1)

        aip, alasttime, atries = attempt
        alasttime = datetime.datetime.fromtimestamp(alasttime)

        if was_current_login_ok is False:
            atries = min(atries+1, 5)
            alasttime = now
        else:
            make_db_call(one="DELETE FROM bad_logins WHERE ip=?", args=(aip,))

        make_db_call(one="UPDATE bad_logins SET last_time=?,tries=? WHERE ip = ?", args=(alasttime, atries, aip))
        
        if atries >= 5:
            return True
        return False
    except Exception as e:
        print(e)
        return False

def is_user_locked_out(ip):
    try:
        tries = make_db_call(one="SELECT tries FROM bad_logins WHERE ip=?", args=(ip, ), fetchone=1)

        if tries is None:
            now = datetime.datetime.now().timestamp()
            make_db_call(one="INSERT INTO bad_logins(ip, last_time) VALUES(?, ?)", args=(ip, now))
            tries = make_db_call(one="SELECT tries FROM bad_logins WHERE ip=?", args=(ip, ), fetchone=1)
        return tries[0] >= 5
    except Exception as err:
        print(err)
        return False

@app.get("/api/login/tries")
def login_tries():
    try:
        make_db_call(one="DELETE FROM bad_logins WHERE last_time < ?", args=((datetime.datetime.now() - timedelta(minutes=5)).timestamp(), ))
        ip = request.remote_addr
        attempt = make_db_call(one="SELECT tries FROM bad_logins WHERE ip = ?", args=(ip,), fetchone=1)
        if attempt is None:
            make_db_call(one="INSERT INTO bad_logins(ip, last_time) VALUES(?, ?)", args=(ip, datetime.datetime.now().timestamp()), fetchone=1)
            attempt = make_db_call(one="SELECT tries FROM bad_logins WHERE ip = ?", args=(ip,), fetchone=1)
        return server_response({"attempt": attempt}, True, 200)
    except Exception as err:
        print(err)
        return server_response("Internal error", False, 500)

@app.post("/api/login")
def login():
    try:
        time.sleep(2.0)
        if is_user_locked_out(request.remote_addr) is True:
            return server_response("You are locked out for 5 minutes", False, 401)

        json_data = request.get_json()
        email = json_data["email"].lower()
        password = json_data["password"]

        if len(email) < 0:
            return server_response("Invalid username or password", False, 401)
        if len(password) < 5:
            return server_response("Invalid username or password", False, 401)
        for l in password:
            if ord(l) > sss.MAX:
                return server_response("Invalid characters in password", False, 401)
        
        user = make_db_call(one="SELECT * FROM users WHERE email = ?", args=(email,), fetchone=1)
        if user is None:
            handle_timed_out_login(request.remote_addr, False)
            return server_response("Invalid username or password", False, 401)
        
        password_indices = make_db_call(one="SELECT i1,i2,i3,i4,i5 FROM user_password_indices WHERE email=?", args=(email,), fetchone=1)
        if password_indices is None:
            raise Exception()

        if len(password_indices) != len(password):
            return server_response("Fill every blank character inside password field", False, 401)
    
        y = user[1]
        z = []
        for i in range(0, len(y), 4):
            z.append(int.from_bytes(y[i:i+4], "big"))
        y = z
        password = [(i, l.encode()) for i,l in zip(password_indices, [*password])]
        rec_secret = sss.reconstruct_secret(password, y)
        if rec_secret == y[-1]:
            handle_timed_out_login(request.remote_addr, True)
            make_db_call(one="DELETE FROM user_password_indices WHERE email=?", args=(email,))
            response = server_response("Login successful", True, 200)
            response = jsonify({"message": 'Login successful', "result": True})
            set_access_cookies(response, create_access_token(identity=email))
            return response

        handle_timed_out_login(request.remote_addr, False)
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

def validate_password(passwd, passwdr):
    if(len(passwd) < 8):
            return server_response("Password cannot be that short", False, 401)
    if(len(passwd) > 16):
        return server_response("Password cannot be that long", False, 401)
    for l in passwd:
        if ord(l) > sss.MAX:
            return server_response("Password contains invalid characters", False, 401)
    if(passwd != passwdr):
        return server_response("Passwords are not the same", False, 401)
    if(make_db_call(one="SELECT COUNT(*) FROM bruteforce_passwords WHERE password LIKE ?", args = (passwd,), fetchone=1)[0] > 0):
        return server_response("Your password is compromised. Please, provide another one.", False, 401)
        
    policy = PasswordPolicy.from_names(strength=(0.66, 7))
    if len(policy.test(password=passwd)) != 0:
        return server_response("Your password is too weak. Please, consider adding uppercase letters, special characters and numbers.", False, 401)
    return server_response("Ok", True, 200)

@app.post("/api/register/validate")
def register_validate():
    try:
        time.sleep(2.0)
        json = request.get_json()
        email = json["email"].lower()
        passwd = json["password"]
        passwdr = json["password_repeat"]
        name = json["name"]
        lastname = json["last_name"]

        if(len(email) == 0):
            return server_response("Email cannot be that short", False, 401)
        if(len(email) > 64):
            return server_response("Email cannot be that long", False, 401)
        if(email.find("@") == -1 or email.find(".") == -1):
            return server_response("Email must have valid format with '@' and '.'", False, 401)
        if(len(name) == 0):
            return server_response("Name cannot be empty", False, 401)
        if(len(name) > 64):
            return server_response("Name cannot be that long", False, 401)
        if(len(lastname) == 0):
            return server_response("Last name cannot be empty", False, 401)
        if(len(lastname) > 64):
            return server_response("Last name cannot be that long", False, 401)
        
        email_already_exists = make_db_call(one="SELECT COUNT(*) FROM users WHERE email == ?", args = (email,), fetchone=1)[0] > 0
        if(email_already_exists):
            return server_response("Email already exists", False, 401)

        pass_result = validate_password(passwd, passwdr) 
        if pass_result[1] != 200:
            return pass_result

        return server_response("Everything is good.", True, 200)
    except Exception as i:
        print(i)
        return server_response("Internal Error", False, 500)

@app.post("/api/register")
def register(override_credentials = None):
    try:
        time.sleep(0.5)
        json = request.get_json(silent=True)
        if json is None:
            raise Exception()

        email = json["email"].lower()
        passwd = json["password"]
        passwdr = json["password_repeat"]
        name = json["name"]
        lastname = json["last_name"]

        if(len(email) == 0):
            return server_response("Email cannot be that short", False, 401)
        if(len(email) > 64):
            return server_response("Email cannot be that long", False, 401)
        if(email.find("@") == -1 or email.find(".") == -1):
            return server_response("Email must have valid format with '@' and '.'", False, 401)
        if(len(name) == 0):
            return server_response("Name cannot be empty", False, 401)
        if(len(name) > 64):
            return server_response("Name cannot be that long", False, 401)
        if(len(lastname) == 0):
            return server_response("Last name cannot be empty", False, 401)
        if(len(lastname) > 64):
            return server_response("Last name cannot be that long", False, 401)

        result = validate_password(passwd, passwdr)
        if result[1] == 200 or override_credentials is not None:
            register_user_in_database(email, passwd, name, lastname)
        return result
    except Exception as err:
        print(err)
        return server_response("Internal Error", False, 500)

def encrypt_user_password(passwd):
    secret = int.from_bytes(hashlib.sha256(passwd.encode()).digest()[:4], "big")
    sh = sss.generate_shares(passwd.encode(), 5, secret)
    sh_str = b""
    for s in sh:
        sh_str += int.to_bytes(s, 4, "big")
    sh_str += int.to_bytes(secret, 4, "big")
    return sh_str

def register_user_in_database(email, passwd, name, lastname):
    sh_str = encrypt_user_password(passwd)
    aes = AES.new(os.getenv("AES_SECRET").encode(), AES.MODE_ECB)
    account_number = aes.encrypt(pad(str(random.randint(1e7, 1e8-1)).encode(), 16))
    while True:
        user_count = make_db_call(one="SELECT COUNT(*) FROM users WHERE account_number = ?", args=(account_number,), fetchone=1)[0]
        if user_count == 0:
            break
        account_number = aes.encrypt(pad(str(random.randint(1e7, 1e8-1)).encode(), 16))

    enc_name = aes.encrypt(pad(name.encode(), 16))
    enc_lastname = aes.encrypt(pad(lastname.encode(), 16))
    enc_bal = aes.encrypt(pad(str(1000.0).encode(), 16))

    make_db_call(one="INSERT INTO users (email, password, account_number, name, lastname, balance) VALUES(?,?,?,?,?,?)", args=(email, sh_str, account_number, enc_name, enc_lastname, enc_bal))

def ecb_dec(bytes):
    return unpad(AES.new(os.getenv("AES_SECRET").encode(), AES.MODE_ECB).decrypt(bytes), 16).decode()
def ecb_enc(bytes):
    return AES.new(os.getenv("AES_SECRET").encode(), AES.MODE_ECB).encrypt(pad(bytes, 16))

@app.post("/api/transfer/make")
@jwt_required(locations=["cookies", "headers"])
def make_transfer():
    try:
        time.sleep(1.0)
        data = request.get_json()
        to = data["to"]
        amount = data["amount"]
        title = data["title"]
        address = data["address"]

        recipient = make_db_call(one="SELECT email, account_number, balance FROM users", fetchall=1)
        recipient_account = ""

        for r in recipient:
            acc = ecb_dec(r[1])
            if acc == to:
                recipient = r
                recipient_account = acc
                break
            else:
                recipient = None

        if recipient is None:
            return server_response("Invalid account number", False, 401)
        
        recipient_email = recipient[0]
        # recipient_account = recipient_account
        recipient_balance = float(ecb_dec(recipient[2]))
        sender_email = get_jwt_identity()
        sender = make_db_call(one="SELECT account_number,balance FROM users WHERE email = ?", args=(sender_email,), fetchone=1)
        sender_account = ecb_dec(sender[0])
        sender_balance = float(ecb_dec(sender[1]))
        print(to, amount, title, address)
        print("EMAIL: ", sender_email)

        if recipient_email == sender_email:
            return server_response("You cannot transfer money to yourself", False, 401)

        if len(title) == 0 or len(address) == 0:
            return server_response("Title and address cannot be empty", False, 401)
        
        try:
            amount = float(amount)
            if amount <= 0.0 or (amount % 1 < 0.01 and amount % 1 > 1e-6):
                raise Exception()
        except Exception as err:
            return server_response("Amount to transfer must be positive real number with fractional part no smaller than 0.01", False, 401)

        if sender_balance < amount:
            return server_response("You cannot transfer more than you have", False, 401)
        
        make_db_call(one="UPDATE users SET balance = ? WHERE email = ?", args=(ecb_enc(str(recipient_balance+amount).encode()), recipient_email))
        make_db_call(one="UPDATE users SET balance = ? WHERE email = ?", args=(ecb_enc(str(sender_balance-amount).encode()), sender_email))
        make_db_call(one="INSERT INTO transfers VALUES (?, ?, ?, ?, ?)", args=(
            sender_account, recipient_account, amount, title, address
        ))
        res = jsonify(message="Transfer was successful", result=True, new_balance=sender_balance-amount)
        return res, 200
    except Exception as err:
        print(err)
        return server_response("Internal error", False, 500)

@app.get("/api/transfer/balance")
@jwt_required(locations=['cookies'])
def get_balance():
    try:
        email = get_jwt_identity()
        balance = make_db_call(one="SELECT balance FROM users WHERE email = ?", args=(email,), fetchone=1)[0]
        balance = unpad(AES.new(os.getenv("AES_SECRET").encode(), AES.MODE_ECB).decrypt(balance), 16).decode()
        return server_response({'balance':balance}, True, 200)
    except Exception as err:
        print(err)
        return server_response("Internal error", False, 500)

@app.get("/api/transfer/history")
@jwt_required(locations=['cookies'])
def get_transfers():
    try:
        email = get_jwt_identity()
        account = ecb_dec(make_db_call(one="SELECT account_number FROM users WHERE email = ?", args=(email, ), fetchone=1)[0])
        history = make_db_call(one="SELECT * FROM transfers WHERE from_account = ? OR to_account = ?", args=(account, account), fetchall=1)
        return server_response({'history':history}, True, 200)
    except Exception as err:
        print(err)
        return server_response("Internal error", False, 500)

@app.get("/api/transfer/account_number")
@jwt_required(locations=['cookies'])
def get_account_number():
    try:
        email = get_jwt_identity()
        account = make_db_call(one="SELECT account_number FROM users WHERE email = ?", args=(email,), fetchone=1)[0]
        account = unpad(AES.new(os.getenv("AES_SECRET").encode(), AES.MODE_ECB).decrypt(account), 16).decode()
        return server_response({'account':account}, True, 200)
    except Exception as err:
        print(err)
        return server_response("Internal error", False, 500)

@app.get("/api/names")
@jwt_required(locations=['cookies'])
def get_names():
    try:
        email = get_jwt_identity()
        account = make_db_call(one="SELECT name, lastname FROM users WHERE email = ?", args=(email,), fetchone=1)
        name = ecb_dec(account[0])
        lastname = ecb_dec(account[1])
        return server_response({'names':(name + " " + lastname)}, True, 200)
    except Exception as err:
        print(err)
        return server_response("Internal error", False, 500)

@app.post("/api/change_password")
def change_password():
    try:
        make_db_call(one="DELETE FROM password_change_requests WHERE issued_date < ?", args=((datetime.datetime.now() - timedelta(minutes=5)).timestamp(), ))
        data = request.get_json()

        if "secret" in data:
            print("detected secret in form's data")
            secret = data["secret"]
            passwd = data["password"]
            passwdr = data["password_repeat"]
            email = make_db_call(one="SELECT email FROM password_change_requests WHERE secret=?", args=(secret, ), fetchone=1)
            if email is None:
                return server_response("Invalid data or secret has expired", False, 401)
            email = email[0]
            result = validate_password(passwd, passwdr)
            if result[1] == 200:
                encrypted = encrypt_user_password(passwd)
                make_db_call(one="DELETE FROM password_change_requests WHERE email=?", args=(email, ))
                make_db_call(one="UPDATE users SET password=? WHERE email=?", args=(encrypted, email))
            return result
        elif "email" in data:
            email = data["email"].lower()
            if len(email) == 0:
                return server_response("Email field cannot be empty when issuing password reset.", False, 401)
            user = make_db_call(one="SELECT COUNT(*) FROM users WHERE email=?", args=(email,), fetchone=1)
            if user is None or user[0] == 0: #if user doesn't exist
                return server_response("Email sent", True, 200)
            db_secret = make_db_call(one="SELECT secret FROM password_change_requests WHERE email=?", args=(email,), fetchone=1)
            if db_secret is not None: #if user already got it's password
                return server_response("Email sent", True, 200) 
            db_secret = str(random.randint(10**7, 10**8-1))
            make_db_call(one="INSERT INTO password_change_requests(email, secret, issued_date) VALUES(?, ?, ?)", args=(email, db_secret, datetime.datetime.now().timestamp())) 
            print(f"Sending to email \"{email}\" secret: \"{db_secret}\"")
            file = open("passwd_change_log", "a")
            file.write(f"Sending to email \"{email}\" secret: \"{db_secret}\"")
            file.close()
            return server_response("Email sent", True, 200) 

        return server_response("Internal error", False, 500)
    except Exception as err:
        print(err)
        return server_response("Internal error", False, 500)

if __name__ == "__main__":
    # make_db_call(one = "DROP TABLE IF EXISTS revoked_jwt")
    # make_db_call(one = "DROP TABLE IF EXISTS transfers")
    # make_db_call(one = "DROP TABLE IF EXISTS users")
    # make_db_call(one = "DROP TABLE IF EXISTS bruteforce_passwords")
    # make_db_call(one = "DROP TABLE IF EXISTS user_password_indices")
    # make_db_call(one = "DROP TABLE IF EXISTS bad_logins")
    # make_db_call(one = "DROP TABLE IF EXISTS password_change_requests")
    make_db_call(one="delete from users where email='admin'")
    make_db_call(one = "DROP TABLE IF EXISTS user_password_indices")

    make_db_call(one = """
    CREATE TABLE IF NOT EXISTS revoked_jwt(
        jti 
    )  
    """)
    make_db_call(one = """
    CREATE TABLE IF NOT EXISTS users(
        email TEXT UNIQUE NOT NULL, 
        password TEXT UNIQUE NOT NULL,
        name BLOB NOT NULL,
        lastname BLOB NOT NULL,
        account_number BLOB UNIQUE NOT NULL,
        balance BLOB NOT NULL
    )
    """)
    make_db_call(one = """
    CREATE TABLE IF NOT EXISTS bruteforce_passwords(
        password TEXT
    )
    """)
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
    make_db_call(one = """
    CREATE TABLE IF NOT EXISTS transfers(
        from_account TEXT NOT NULL,
        to_account TEXT NOT NULL,
        amount REAL NOT NULL,
        title TEXT NOT NULL,
        address TEXT NOT NULL
    )
    """)
    make_db_call(one = """
    CREATE TABLE IF NOT EXISTS bad_logins(
        ip TEXT UNIQUE NOT NULL,
        last_time REAL NOT NULL,
        tries INTEGER DEFAULT 0
    )
    """)
    make_db_call(one = """
    CREATE TABLE IF NOT EXISTS password_change_requests(
        email TEXT UNIQUE NOT NULL,
        secret TEXT UNIQUE NOT NULL,
        issued_date REAL NOT NULL
    )
    """)

    register_user_in_database("admin", "admin", "a", "b")
    register_user_in_database("karol", "karol", "kar", "kub")

    if make_db_call(one="SELECT COUNT(*) FROM bruteforce_passwords", fetchone=1)[0] == 0:
        file = open("passwords.txt", 'r')
        passwords = [ (x,) for x in file.read().splitlines() ]
        file.close()
        make_db_call(many = """
        INSERT INTO bruteforce_passwords VALUES(?)
        """, args=passwords)

    serve(app, host="0.0.0.0", port=8080, url_scheme="https", threads=4)
