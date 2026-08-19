import sqlite3
from datetime import datetime

from config import DATABASE_FILE
from security import hash_password, verify_password


def connect():
    connection = sqlite3.connect(DATABASE_FILE)
    connection.row_factory = sqlite3.Row
    return connection


def create_database():
    with connect() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                full_name TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                role TEXT NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1,
                must_change_password INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_code TEXT UNIQUE NOT NULL,
                title TEXT NOT NULL,
                incident_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL,
                owner_username TEXT NOT NULL,
                created_by TEXT NOT NULL,
                report_path TEXT NOT NULL,
                stored_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_code TEXT NOT NULL,
                original_name TEXT NOT NULL,
                stored_path TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                uploaded_by TEXT NOT NULL,
                uploaded_at TEXT NOT NULL
            );
            """
        )


def user_count():
    with connect() as connection:
        row = connection.execute("SELECT COUNT(*) AS total FROM users").fetchone()
        return row["total"]


def create_user(username, full_name, password, role, must_change_password=False):
    password_hash, salt = hash_password(password)

    with connect() as connection:
        connection.execute(
            """
            INSERT INTO users (
                username, full_name, password_hash, salt, role,
                is_active, must_change_password, created_at
            )
            VALUES (?, ?, ?, ?, ?, 1, ?, ?)
            """,
            (
                username.strip().lower(),
                full_name.strip(),
                password_hash,
                salt,
                role,
                1 if must_change_password else 0,
                datetime.now().isoformat(timespec="seconds"),
            ),
        )


def authenticate_user(username, password):
    with connect() as connection:
        user = connection.execute(
            "SELECT * FROM users WHERE username = ?",
            (username.strip().lower(),),
        ).fetchone()

    if user is None or not user["is_active"]:
        return None

    if verify_password(password, user["password_hash"], user["salt"]):
        return dict(user)

    return None


def list_users():
    with connect() as connection:
        rows = connection.execute(
            """
            SELECT id, username, full_name, role, is_active, created_at
            FROM users
            ORDER BY username
            """
        ).fetchall()

    return [dict(row) for row in rows]


def set_user_active(user_id, active):
    with connect() as connection:
        connection.execute(
            "UPDATE users SET is_active = ? WHERE id = ?",
            (1 if active else 0, user_id),
        )


def reset_user_password(user_id, new_password):
    password_hash, salt = hash_password(new_password)

    with connect() as connection:
        connection.execute(
            """
            UPDATE users
            SET password_hash = ?, salt = ?, must_change_password = 1
            WHERE id = ?
            """,
            (password_hash, salt, user_id),
        )


def change_password(user_id, new_password):
    password_hash, salt = hash_password(new_password)

    with connect() as connection:
        connection.execute(
            """
            UPDATE users
            SET password_hash = ?, salt = ?, must_change_password = 0
            WHERE id = ?
            """,
            (password_hash, salt, user_id),
        )


def add_incident(
    incident_code,
    title,
    incident_type,
    severity,
    status,
    owner_username,
    created_by,
    report_path,
    stored_hash,
):
    now = datetime.now().isoformat(timespec="seconds")

    with connect() as connection:
        connection.execute(
            """
            INSERT INTO incidents (
                incident_code, title, incident_type, severity, status,
                owner_username, created_by, report_path, stored_hash,
                created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                incident_code,
                title,
                incident_type,
                severity,
                status,
                owner_username,
                created_by,
                report_path,
                stored_hash,
                now,
                now,
            ),
        )


def update_incident_status_and_hash(incident_code, status, stored_hash=None):
    with connect() as connection:
        if stored_hash is None:
            connection.execute(
                """
                UPDATE incidents
                SET status = ?, updated_at = ?
                WHERE incident_code = ?
                """,
                (
                    status,
                    datetime.now().isoformat(timespec="seconds"),
                    incident_code,
                ),
            )
        else:
            connection.execute(
                """
                UPDATE incidents
                SET status = ?, stored_hash = ?, updated_at = ?
                WHERE incident_code = ?
                """,
                (
                    status,
                    stored_hash,
                    datetime.now().isoformat(timespec="seconds"),
                    incident_code,
                ),
            )


def update_incident_hash(incident_code, stored_hash):
    with connect() as connection:
        connection.execute(
            """
            UPDATE incidents
            SET stored_hash = ?, updated_at = ?
            WHERE incident_code = ?
            """,
            (
                stored_hash,
                datetime.now().isoformat(timespec="seconds"),
                incident_code,
            ),
        )


def get_incident(incident_code):
    with connect() as connection:
        row = connection.execute(
            "SELECT * FROM incidents WHERE incident_code = ?",
            (incident_code,),
        ).fetchone()

    return dict(row) if row else None


def list_incidents(username, role):
    with connect() as connection:
        if role == "analyst":
            rows = connection.execute(
                """
                SELECT * FROM incidents
                WHERE owner_username = ?
                ORDER BY created_at DESC
                """,
                (username,),
            ).fetchall()
        else:
            rows = connection.execute(
                "SELECT * FROM incidents ORDER BY created_at DESC"
            ).fetchall()

    return [dict(row) for row in rows]


def add_evidence(
    incident_code,
    original_name,
    stored_path,
    sha256,
    uploaded_by,
):
    with connect() as connection:
        connection.execute(
            """
            INSERT INTO evidence (
                incident_code, original_name, stored_path,
                sha256, uploaded_by, uploaded_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                incident_code,
                original_name,
                stored_path,
                sha256,
                uploaded_by,
                datetime.now().isoformat(timespec="seconds"),
            ),
        )


def list_evidence(incident_code):
    with connect() as connection:
        rows = connection.execute(
            """
            SELECT * FROM evidence
            WHERE incident_code = ?
            ORDER BY uploaded_at DESC
            """,
            (incident_code,),
        ).fetchall()

    return [dict(row) for row in rows]
