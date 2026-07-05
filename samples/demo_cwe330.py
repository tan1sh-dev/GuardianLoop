# Intentionally vulnerable sample: CWE-330 insecure randomness.
#
# The standard random module uses the Mersenne Twister PRNG, which is
# completely predictable. It must never be used for security tokens,
# passwords, or session IDs.
#
# A correct patch must replace random with the secrets module:
#   import secrets
#   token = secrets.token_hex(16)

import random
import string


def generate_session_token(length=32):
    # VULNERABLE: random.choice is predictable — attacker can predict tokens.
    chars = string.ascii_letters + string.digits
    token = "".join(random.choice(chars) for _ in range(length))
    return token


def generate_password_reset_code():
    # VULNERABLE: random.randint is predictable.
    code = random.randint(100000, 999999)
    return str(code)


def generate_api_key():
    # VULNERABLE: random.getrandbits is predictable.
    key = hex(random.getrandbits(128))
    return key


if __name__ == "__main__":
    print(f"Session token: {generate_session_token()}")
    print(f"Reset code: {generate_password_reset_code()}")
    print(f"API key: {generate_api_key()}")
