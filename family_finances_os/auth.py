"""
Family Finances OS - Authentication & User Management Service
"""
import sqlite3
from typing import Optional, Dict, Any
from family_finances_os.db import get_db_connection, GLOBAL_STORAGE
from family_finances_os.security import hash_password, verify_password, SessionManager
from family_finances_os.models import generate_uuid, current_iso_time

# Global session manager instance
GLOBAL_SESSION_MANAGER = SessionManager()


class AuthService:
    def __init__(self, conn_or_path: Any = None, session_manager: Optional[SessionManager] = None):
        self.conn_or_path = conn_or_path
        self.session_manager = session_manager or GLOBAL_SESSION_MANAGER

    def _get_conn(self) -> sqlite3.Connection:
        return get_db_connection(self.conn_or_path)

    def _close_if_local(self, conn: sqlite3.Connection):
        if isinstance(self.conn_or_path, sqlite3.Connection):
            return
        if GLOBAL_STORAGE.is_unlocked() and conn is GLOBAL_STORAGE.get_connection():
            return
        if self.conn_or_path:
            conn.close()
            return
        from family_finances_os.config import DB_PATH
        if DB_PATH.exists() and not GLOBAL_STORAGE.is_unlocked():
            conn.close()

    def _save_if_encrypted(self):
        if GLOBAL_STORAGE.is_unlocked():
            GLOBAL_STORAGE.save()

    def has_owner(self) -> bool:
        """Check if a Family Owner account has already been created."""
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT count(*) FROM users WHERE role = 'OWNER' AND is_active = 1;")
        count = cursor.fetchone()[0]
        self._close_if_local(conn)
        return count > 0

    def create_owner(self, username: str, display_name: str, password: str) -> Dict[str, Any]:
        """
        Create the initial Family Owner user and corresponding member entry.
        Enforces 600,000 PBKDF2-HMAC-SHA256 iterations.
        """
        if self.has_owner():
            raise ValueError("Family Owner already exists! Only one owner can be created during initial setup.")
        if len(password) < 6:
            raise ValueError("Password must be at least 6 characters long.")
        if not username.strip():
            raise ValueError("Username cannot be empty.")

        pwd_hash, salt = hash_password(password)
        user_id = generate_uuid()
        member_id = generate_uuid()

        conn = self._get_conn()
        cursor = conn.cursor()
        try:
            # 1. Insert user
            cursor.execute("""
            INSERT INTO users (id, username, display_name, role, password_hash, salt, is_active)
            VALUES (?, ?, ?, 'OWNER', ?, ?, 1)
            """, (user_id, username.strip(), display_name.strip(), pwd_hash, salt))

            # 2. Insert member
            cursor.execute("""
            INSERT INTO members (id, user_id, display_name, role, color_hex)
            VALUES (?, ?, ?, 'OWNER', '#2563EB')
            """, (member_id, user_id, display_name.strip()))

            # 3. Store family metadata
            cursor.execute("""
            INSERT OR REPLACE INTO system_meta (key, value) VALUES ('family_initialized', '1');
            """)
            cursor.execute("""
            INSERT OR REPLACE INTO system_meta (key, value) VALUES ('owner_user_id', ?);
            """, (user_id,))
            conn.commit()
            self._save_if_encrypted()
        finally:
            self._close_if_local(conn)

        return {
            "user_id": user_id,
            "member_id": member_id,
            "username": username.strip(),
            "display_name": display_name.strip(),
            "role": "OWNER"
        }

    def authenticate(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """
        Authenticate user with password.
        Returns user dictionary and valid session token on success, None on failure.
        """
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute("""
        SELECT u.id, u.username, u.display_name, u.role, u.password_hash, u.salt, u.is_active, m.id as member_id
        FROM users u
        LEFT JOIN members m ON u.id = m.user_id
        WHERE u.username = ? AND u.is_active = 1
        """, (username.strip(),))
        row = cursor.fetchone()
        self._close_if_local(conn)

        if not row:
            return None

        expected_hash = row["password_hash"]
        salt = row["salt"]

        if verify_password(password, expected_hash, salt):
            user_data = {
                "user_id": row["id"],
                "member_id": row["member_id"],
                "username": row["username"],
                "display_name": row["display_name"],
                "role": row["role"]
            }
            token = self.session_manager.create_session(user_data)
            user_data["session_token"] = token
            return user_data
        return None

    def validate_session(self, token: Optional[str]) -> Optional[Dict[str, Any]]:
        """Validate an active session token."""
        return self.session_manager.validate_session(token)

    def logout(self, token: Optional[str]) -> bool:
        """Terminate and invalidate a session."""
        return self.session_manager.invalidate_session(token)

    def change_password(self, user_id: str, old_password: str, new_password: str) -> bool:
        """Change user password after verifying old password."""
        if len(new_password) < 6:
            raise ValueError("New password must be at least 6 characters long.")

        conn = self._get_conn()
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT password_hash, salt FROM users WHERE id = ?", (user_id,))
            row = cursor.fetchone()
            if not row:
                return False

            if not verify_password(old_password, row["password_hash"], row["salt"]):
                return False

            new_hash, new_salt = hash_password(new_password)
            cursor.execute("UPDATE users SET password_hash = ?, salt = ? WHERE id = ?", (new_hash, new_salt, user_id))
            conn.commit()
            self._save_if_encrypted()
            return True
        finally:
            self._close_if_local(conn)
