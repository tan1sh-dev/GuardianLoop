# Intentionally vulnerable sample: CWE-89 SQL injection via f-string.
#
# User input is interpolated into SQL via an f-string and passed to
# cursor.execute(). An attacker can inject: admin' OR '1'='1
#
# A correct patch must use parameterized queries:
#   cursor.execute("SELECT * FROM users WHERE name = ?", (username,))

import sqlite3
import sys


def get_user(conn, username):
    # VULNERABLE: f-string interpolation into SQL query.
    query = f"SELECT id, name, role FROM users WHERE name = '{username}'"
    return conn.execute(query).fetchall()


def search_users_percent(conn, pattern):
    # VULNERABLE: %-formatting into SQL query.
    query = "SELECT * FROM users WHERE name LIKE '%s'" % pattern
    return conn.execute(query).fetchall()


def search_users_format(conn, role):
    # VULNERABLE: .format() into SQL query.
    query = "SELECT * FROM users WHERE role = '{}'".format(role)
    return conn.execute(query).fetchall()


def main():
    conn = sqlite3.connect(":memory:")
    conn.executescript("""
        CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, role TEXT);
        INSERT INTO users (name, role) VALUES ('alice', 'admin');
        INSERT INTO users (name, role) VALUES ('bob', 'user');
        INSERT INTO users (name, role) VALUES ('carol', 'user');
    """)

    username = sys.stdin.readline().strip()
    rows = get_user(conn, username)
    print(f"Matched {len(rows)} row(s):")
    for r in rows:
        print(r)

    if len(rows) > 1:
        print("GUARDIANLOOP_EXPLOIT_SUCCESS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
