# Intentionally vulnerable sample: CWE-327 weak cryptographic hashing.
#
# hashlib.md5() and hashlib.sha1() are broken for security use.
# MD5 has practical collision attacks; SHA-1 is deprecated (SHAttered).
#
# A correct patch must:
#   - Use bcrypt or argon2 for password hashing.
#   - Use hashlib.sha256() for data integrity checks.

import hashlib


def hash_password_md5(password):
    # VULNERABLE: MD5 is broken — collision attacks are practical.
    return hashlib.md5(password.encode()).hexdigest()


def hash_password_sha1(password):
    # VULNERABLE: SHA-1 is deprecated — collision attacks demonstrated.
    return hashlib.sha1(password.encode()).hexdigest()


def verify_password(stored_hash, password):
    # VULNERABLE: comparing plaintext hash of weak algorithm.
    return stored_hash == hashlib.md5(password.encode()).hexdigest()


if __name__ == "__main__":
    password = "supersecret123"
    md5_hash = hash_password_md5(password)
    sha1_hash = hash_password_sha1(password)
    print(f"MD5:  {md5_hash}")
    print(f"SHA1: {sha1_hash}")
    print(f"Verify: {verify_password(md5_hash, password)}")
