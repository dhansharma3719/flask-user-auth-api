# Flask User Authentication & Authorization API

A secure REST API built with Flask and SQLite implementing full user
management and JWT-based authentication from scratch — no external
auth libraries used.

> **Note:** Built as part of CSE 380 (Information Management and the Cloud)
> at Michigan State University. All authentication logic implemented manually
> per course requirements.

---

## What This Does

A production-style backend authentication system that handles:
- User registration with password validation and SHA-256 hashing
- Login with JWT token generation
- JWT-protected endpoints for viewing and updating user data
- Password history tracking to prevent password reuse
- SQL injection protection via parameterized queries

---

## Tech Stack

- **Language:** Python 3
- **Framework:** Flask
- **Database:** SQLite3 (built-in)
- **Auth:** JWT (HS256) — implemented from scratch using `hmac` + `hashlib`
- **Security:** SHA-256 password hashing with salt, parameterized SQL queries

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/clear` | Reset database to clean state |
| POST | `/create_user` | Register a new user |
| POST | `/login` | Authenticate and receive JWT |
| POST | `/update` | Update username or password (JWT required) |
| POST | `/view` | View account details (JWT required) |

---

## Security Features

**Password Validation**
- Minimum 8 characters
- Must contain uppercase, lowercase, and a digit
- Cannot match username, first name, or last name
- Cannot reuse any previously used password

**Password Storage**
- Never stored in plaintext
- Hashed using SHA-256 with a unique per-user salt
- Same salt used consistently across all password changes

**JWT Authentication**
- Header + payload Base64 URL-encoded
- Signature generated using HMAC-SHA256 with a secret key from `key.txt`
- Token verified on every protected request — checks signature, username, and access field

**SQL Injection Protection**
- All user-supplied input handled via parameterized queries

---

## JWT Format

```
<base64url(header)>.<base64url(payload)>.<hmac_sha256_signature>

Header:  { "alg": "HS256", "typ": "JWT" }
Payload: { "username": "<user>", "access": "True" }
```

---

## Response Format Examples

**POST /create_user**
```json
{ "status": 1, "pass_hash": "<sha256_hash>" }
```
Status codes: `1` = success, `2` = duplicate username,
`3` = duplicate email, `4` = invalid password

**POST /login**
```json
{ "status": 1, "jwt": "<token>" }
```
Status codes: `1` = success, `2` = invalid credentials

**POST /update**
```json
{ "status": 1 }
```
Status codes: `1` = success, `2` = bad credentials, `3` = invalid JWT

**POST /view**
```json
{
  "status": 1,
  "data": {
    "username": "...",
    "email_address": "...",
    "first_name": "...",
    "last_name": "..."
  }
}
```

---

## How To Run

```bash
pip install flask
flask run --debug
```

Server runs on `http://127.0.0.1:5000`

Requires a `key.txt` file in the root directory containing the HMAC signing key,
and a `project1.sql` file to initialize the database schema.
