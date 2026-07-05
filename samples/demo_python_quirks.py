# Intentionally vulnerable sample: Python-specific configuration quirks.
#
# Three vulnerabilities:
#   1. CWE-1188: Mutable default argument — list shared across calls.
#   2. CWE-617: assert for authorization — stripped in optimized mode (-O).
#   3. CWE-377: tempfile.mktemp() — race condition in temp file creation.
#
# Correct patches:
#   1. Use None as default: def func(items=None): items = items or []
#   2. Use if-not-raise: if not user.is_admin: raise PermissionError(...)
#   3. Use tempfile.mkstemp() or tempfile.NamedTemporaryFile()

import tempfile


class User:
    def __init__(self, name, is_admin=False):
        self.name = name
        self.is_admin = is_admin


# VULNERABLE: mutable default argument — the list is shared across all calls.
def add_role(user_name, roles=[]):
    roles.append("viewer")
    return {"user": user_name, "roles": roles}


# VULNERABLE: assert for authorization — stripped with python -O.
def delete_database(user):
    assert user.is_admin
    print(f"Database deleted by {user.name}")


# VULNERABLE: tempfile.mktemp() is a race condition.
def create_report():
    report_path = tempfile.mktemp(suffix=".txt")
    with open(report_path, "w") as f:
        f.write("Confidential report data")
    return report_path


if __name__ == "__main__":
    # Mutable default: second call inherits roles from first call
    print(add_role("alice"))   # {'user': 'alice', 'roles': ['viewer']}
    print(add_role("bob"))     # {'user': 'bob', 'roles': ['viewer', 'viewer']} — BUG!

    # Assert bypass: run with python -O demo_python_quirks.py
    admin = User("admin", is_admin=True)
    attacker = User("attacker", is_admin=False)
    delete_database(admin)
    # delete_database(attacker)  # Would raise AssertionError... unless -O flag

    # Insecure temp file
    path = create_report()
    print(f"Report written to: {path}")
