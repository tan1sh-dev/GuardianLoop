"""
Intentionally vulnerable sample: CWE-89 SQL injection via string concatenation.

Reads a username from stdin and looks it up in an in-memory sqlite database
using an f-string interpolated directly into the SQL text. When the input
contains ``admin' OR '1'='1``, the query matches every row. The sample prints
``GUARDIANLOOP_EXPLOIT_SUCCESS`` as a marker so the Red-Team sandbox harness
can detect that the exploit worked.

A correct patch must use parameterized queries (``?`` placeholders), which
makes the malicious payload a literal username that matches zero rows.
"""

import sqlite3
import sys


def get_user(conn: sqlite3.Connection, username: str):
    # VULNERABLE: attacker-controlled string interpolated into SQL.
    query = f"SELECT id, name, role FROM users WHERE name = '{username}'"
    return conn.execute(query).fetchall()


def main() -> int:
    conn = sqlite3.connect(":memory:")
    conn.executescript(
        """
        CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, role TEXT);
        INSERT INTO users (name, role) VALUES ('alice', 'admin');
        INSERT INTO users (name, role) VALUES ('bob', 'user');
        INSERT INTO users (name, role) VALUES ('carol', 'user');
        """
    )

    username = sys.stdin.readline().strip()
    rows = get_user(conn, username)
    print(f"Matched {len(rows)} row(s):")
    for r in rows:
        print(r)

    # Heuristic: a single-user lookup that returns more than one row means the
    # attacker's `OR '1'='1` payload broke out of the quoted string context.
    if len(rows) > 1:
        print("GUARDIANLOOP_EXPLOIT_SUCCESS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
