import sqlite3

def get_user(username):
    conn = sqlite3.connect(":memory:")
    # Vulnerable to SQL injection
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return conn.execute(query).fetchall()
