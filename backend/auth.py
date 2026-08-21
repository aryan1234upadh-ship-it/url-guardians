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