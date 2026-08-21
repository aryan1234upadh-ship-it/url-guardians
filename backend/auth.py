import os
import jwt
import bcrypt
from datetime import datetime, timedelta
from database import get_db
from dotenv import load_dotenv

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY", "url-guardians-secret-key-2025")
ALGORITHM = "HS256"
TOKEN_EXPIRE_HOURS = 24

def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt).decode()

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())

def create_token(username: str) -> str:
    payload = {
        "sub": username,
        "exp": datetime.utcnow() + timedelta(hours=TOKEN_EXPIRE_HOURS),
        "iat": datetime.utcnow()
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("sub")
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def register_user(username: str, email: str, password: str) -> dict:
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT id FROM users WHERE username=? OR email=?", (username, email))
        if cursor.fetchone():
            return {"success": False, "message": "Username or email already exists!"}
        if len(password) < 8:
            return {"success": False, "message": "Password must be at least 8 characters!"}
        password_hash = hash_password(password)
        cursor.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
            (username, email, password_hash)
        )
        conn.commit()
        return {"success": True, "message": "Account created successfully!"}
    except Exception as e:
        return {"success": False, "message": str(e)}
    finally:
        conn.close()

def login_user(username: str, password: str) -> dict:
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT * FROM users WHERE username=? AND is_active=1", (username,))
        user = cursor.fetchone()
        if not user:
            return {"success": False, "message": "Invalid username or password!"}
        if not verify_password(password, user["password_hash"]):
            return {"success": False, "message": "Invalid username or password!"}
        token = create_token(username)
        return {
            "success": True,
            "token": token,
            "username": username,
            "is_admin": bool(user["is_admin"]),
            "message": "Login successful!"
        }
    except Exception as e:
        return {"success": False, "message": str(e)}
    finally:
        conn.close()
