"""Generate a PBKDF2-HMAC-SHA256 credential for Streamlit staff secrets."""

import getpass
import hashlib
import secrets


def main():
    password = getpass.getpass("Staff password: ")
    if not password:
        raise SystemExit("Password cannot be empty.")
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200000)
    print(f'salt = "{salt.hex()}"')
    print(f'hash = "{digest.hex()}"')


if __name__ == "__main__":
    main()
