# Intentionally vulnerable sample: CWE-89 SQL Injection + CWE-78 Command Injection.
# Used as the GuardianLoop `make demo` smoke-test target.
#
# vulnerability 1 — SQL injection via f-string query construction.
# An attacker who controls `username` can terminate the query and append
# arbitrary SQL (e.g. "' OR '1'='1" to bypass authentication).
#
# vulnerability 2 — OS command injection via os.system with user input.
# An attacker who controls `filename` can inject shell metacharacters
# (e.g. "; rm -rf /") to execute arbitrary commands.

import os
import sqlite3


def get_user(db: sqlite3.Connection, username: str) -> list:
    # VULNERABLE: user input interpolated directly into the query string.
    query = f"SELECT * FROM users WHERE name = '{username}'"
    return db.execute(query).fetchall()


def export_report(filename: str) -> None:
    # VULNERABLE: user-controlled filename passed to a shell command.
    os.system(f"cat reports/{filename} >> /tmp/export.log")
