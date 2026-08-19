from datetime import datetime
import hashlib
import hmac
import secrets

from config import ACTIVITY_LOG, SECURITY_LOG


def hash_password(password, salt=None):
    """Return a secure PBKDF2 password hash and salt."""
    if salt is None:
        salt = secrets.token_hex(16)

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        120_000,
    ).hex()

    return password_hash, salt


def verify_password(password, stored_hash, stored_salt):
    entered_hash, _ = hash_password(password, stored_salt)
    return hmac.compare_digest(entered_hash, stored_hash)


def hash_file(file_path):
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        for block in iter(lambda: file.read(4096), b""):
            sha256.update(block)

    return sha256.hexdigest()


def _write_log(log_file, message):
    timestamp = datetime.now().strftime("%d-%m-%Y %H:%M:%S")

    with open(log_file, "a", encoding="utf-8") as file:
        file.write(f"[{timestamp}] {message}\n")


def log_activity(message):
    _write_log(ACTIVITY_LOG, message)


def log_security(message):
    _write_log(SECURITY_LOG, message)


def read_log(log_file):
    try:
        with open(log_file, "r", encoding="utf-8") as file:
            return file.read()
    except FileNotFoundError:
        return "No records available."
