import sqlite3
import os
from flask import Flask, request, jsonify
import hashlib, base64, json, hmac

app = Flask(__name__)
db_name = "project1.db"
sql_file = "project1.sql"
db_flag = False

def valid_password(password, username, first_name, last_name):
    if len(password) < 8:
        return False
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    if not (has_upper and has_lower and has_digit):
        return False
	# if password == username and password == first_name and password == last_name:

    if password == username or password == first_name or password == last_name:
        return False
    return True

def jwt_verification(jwt_token):
	try:
		token_break = jwt_token.split('.')
		if len(token_break)!= 3:
			return None
		header_b64, payload_b64, signature = token_break

		with open("key.txt","r") as file:
			key = file.read().strip()
		message = f"{header_b64}.{payload_b64}".encode('utf-8')

		new_signature = hmac.new(
			key.encode('utf-8'),
			message,
			hashlib.sha256
		).hexdigest()

		if signature != new_signature:
			return None
		
		x_payload = payload_b64 + '=' * (-len(payload_b64)%4)
		json_payload = base64.urlsafe_b64decode(x_payload.encode('utf-8')).decode('utf-8')
		final_payload= json.loads(json_payload)

		if final_payload.get("access")!= "True":
			return None
		
		return final_payload.get("username")
	except:
		return None


def create_db():
    conn = sqlite3.connect(db_name)
    
    with open(sql_file, 'r') as sql_startup:
    	init_db = sql_startup.read()
    cursor = conn.cursor()
    cursor.executescript(init_db)
    conn.commit()
    conn.close()
    global db_flag
    db_flag = True
    # return conn

def get_db():
	if not db_flag:
		create_db()
	conn = sqlite3.connect(db_name)
	return conn

@app.route('/', methods=(['GET']))
def index():
	conn = get_db()
	cursor = conn.cursor()
	cursor.execute("SELECT * FROM test;")
	result = cursor.fetchall()
	conn.close()

	return result

@app.route('/clear', methods=['GET'])
def clear():
    global db_flag
    try:
        if os.path.exists(db_name):
            os.remove(db_name)
        db_flag = False
    except:
        pass
    return jsonify({})

@app.route('/create_user', methods=['POST'])
def create_user():

    first_name = request.form.get('first_name')
    last_name = request.form.get('last_name')
    username = request.form.get('username')
    email_address = request.form.get('email_address')
    password = request.form.get('password')
    salt = request.form.get('salt')

    if not valid_password(password, username, first_name, last_name):
        return jsonify({
            "status": 4,
            "pass_hash": "NULL"
        })

    conn = get_db()
    try:
        cursor = conn.cursor()

        cursor.execute("SELECT 1 FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            return jsonify({
                "status": 2,
                "pass_hash": "NULL"
            })

        cursor.execute("SELECT 1 FROM users WHERE email_address = ?", (email_address,))
        if cursor.fetchone():
            return jsonify({
                "status": 3,
                "pass_hash": "NULL"
            })

        pass_hash = hashlib.sha256((password + salt).encode('utf-8')).hexdigest()

        cursor.execute("""
            INSERT INTO users (first_name, last_name, username, email_address, pass_hash, salt)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (first_name, last_name, username, email_address, pass_hash, salt))

        user_id = cursor.lastrowid

        cursor.execute("""
            INSERT INTO password_history (user_id, pass_hash)
            VALUES (?, ?)
        """, (user_id, pass_hash))

        conn.commit()
    finally:
        conn.close()

    return jsonify({
        "status": 1,
        "pass_hash": pass_hash
    })

@app.route('/login', methods=['POST'])
def login():

    username = request.form.get('username')
    password = request.form.get('password')

    conn = get_db()
    try:
        cursor = conn.cursor()

        cursor.execute("SELECT pass_hash, salt FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()

        if not result:
            return jsonify({
                "status": 2,
                "jwt": "NULL"
            })

        stored_hash, salt = result
        input_hash = hashlib.sha256((password + salt).encode('utf-8')).hexdigest()

        if input_hash != stored_hash:
            return jsonify({
                "status": 2,
                "jwt": "NULL"
            })

        header = {
            "alg": "HS256",
            "typ": "JWT"
        }

        payload = {
            "username": username,
            "access": "True"
        }

        header_b64 = base64.urlsafe_b64encode(
            json.dumps(header, separators=(', ', ': ')).encode('utf-8')
        ).decode('utf-8')

        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(payload, separators=(', ', ': ')).encode('utf-8')
        ).decode('utf-8')

        with open("key.txt", "r") as f:
            key = f.read().strip()

        message = f"{header_b64}.{payload_b64}".encode('utf-8')

        signature = hmac.new(
            key.encode('utf-8'),
            message,
            hashlib.sha256
        ).hexdigest()

        jwt_token = f"{header_b64}.{payload_b64}.{signature}"

        return jsonify({
            "status": 1,
            "jwt": jwt_token
        })

    finally:
        conn.close()

# @app.route('/update', methods=['POST'])
# def update():
# 	jwt_token = request.form.get('jwt')
# 	token_username = jwt_verification(jwt_token)

# 	if not token_username:
# 		return jsonify({"status": 3})
# 	conn = get_db()

# 	try:
# 		cursor = conn.cursor()
# 		if request.form.get('new_username'):
# 			old_username = request.form.get('username')
# 			new_username = request.form.get('new_username')

# 			if old_username != token_username:
# 				return jsonify({"status": 2})
			
# 			cursor.execute("UPDATE users SET username = ? WHERE username = ?",(new_username, old_username))
# 			conn.commit()

@app.route('/update', methods=['POST'])
def update():

    jwt_token = request.form.get('jwt')
    token_username = jwt_verification(jwt_token)

    if not token_username:
        return jsonify({"status": 3})

    conn = get_db()
    try:
        cursor = conn.cursor()

        if request.form.get('new_username'):

            old_username = request.form.get('username')
            new_username = request.form.get('new_username')

            if old_username != token_username:
                return jsonify({"status": 2})

            cursor.execute("SELECT 1 FROM users WHERE username = ?", (new_username,))
            if cursor.fetchone():
                return jsonify({"status": 2})

            cursor.execute(
                "UPDATE users SET username = ? WHERE username = ?",
                (new_username, old_username)
            )
            conn.commit()

            return jsonify({"status": 1})

        elif request.form.get('new_password'):

            old_password = request.form.get('password')
            new_password = request.form.get('new_password')

            cursor.execute(
                "SELECT pass_hash, salt, first_name, last_name FROM users WHERE username = ?",
                (token_username,)
            )
            result = cursor.fetchone()

            if not result:
                return jsonify({"status": 2})

            stored_hash, salt, first_name, last_name = result

            old_hash = hashlib.sha256((old_password + salt).encode('utf-8')).hexdigest()

            if old_hash != stored_hash:
                return jsonify({"status": 2})

            if not valid_password(new_password, token_username, first_name, last_name):
                return jsonify({"status": 2})

            new_hash = hashlib.sha256((new_password + salt).encode('utf-8')).hexdigest()

            cursor.execute(
                "SELECT 1 FROM password_history WHERE user_id = "
                "(SELECT id FROM users WHERE username = ?) AND pass_hash = ?",
                (token_username, new_hash)
            )

            if cursor.fetchone():
                return jsonify({"status": 2})

            cursor.execute(
                "UPDATE users SET pass_hash = ? WHERE username = ?",
                (new_hash, token_username)
            )

            cursor.execute(
                "INSERT INTO password_history (user_id, pass_hash) "
                "VALUES ((SELECT id FROM users WHERE username = ?), ?)",
                (token_username, new_hash)
            )

            conn.commit()

            return jsonify({"status": 1})

        else:
            return jsonify({"status": 2})

    finally:
        conn.close()      

@app.route('/view', methods=['POST'])
def view():

    jwt_token = request.form.get('jwt')
    token_username = jwt_verification(jwt_token)

    if not token_username:
        return jsonify({
            "status": 2,
            "data": "NULL"
        })

    conn = get_db()
    try:
        cursor = conn.cursor()

        cursor.execute(
            "SELECT username, email_address, first_name, last_name FROM users WHERE username = ?",
            (token_username,)
        )

        result = cursor.fetchone()

        if not result:
            return jsonify({
                "status": 2,
                "data": "NULL"
            })

        username, email, first_name, last_name = result

        return jsonify({
            "status": 1,
            "data": {
                "username": username,
                "email_address": email,
                "first_name": first_name,
                "last_name": last_name
            }
        })

    finally:
        conn.close()