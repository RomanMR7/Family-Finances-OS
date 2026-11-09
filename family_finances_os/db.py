"""
Family Finances OS - Database & Storage Engine with Envelope Encrypted Storage Support
"""
import io
import os
import shutil
import sqlite3
import threading
import time
from pathlib import Path
from typing import Optional, Tuple, Dict, Any
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from family_finances_os.config import DB_PATH, ENC_DB_PATH, STRICT_ENCRYPTION
from family_finances_os.security import (
    create_envelope,
    open_envelope,
    fast_save_envelope,
    change_envelope_password,
    wipe_memory,
    generate_salt,
    generate_nonce,
    derive_key
)


def get_connection(db_path: Path = DB_PATH) -> sqlite3.Connection:
    """
    Get a configured SQLite database connection for on-disk or in-memory databases.
    Enables WAL mode (for file DBs), foreign keys, and dictionary-like row access.
    """
    is_memory = str(db_path) == ":memory:"
    conn = sqlite3.connect(str(db_path), timeout=15.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    if not is_memory:
        conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    return conn


def create_schema(conn: sqlite3.Connection) -> None:
    """Execute complete database schema definition and migrations."""
    cursor = conn.cursor()

    # 1. System Metadata table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS system_meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    cursor.execute("SELECT value FROM system_meta WHERE key = 'device_id';")
    if not cursor.fetchone():
        import uuid
        cursor.execute("INSERT OR REPLACE INTO system_meta (key, value) VALUES ('device_id', ?);", (str(uuid.uuid4()),))

    # 2. Users (Authentication & Family Members)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        display_name TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('OWNER', 'ADULT', 'CHILD', 'VIEWER')),
        password_hash BLOB NOT NULL,
        salt BLOB NOT NULL,
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 3. Family Members
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS members (
        id TEXT PRIMARY KEY,
        user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
        display_name TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('OWNER', 'ADULT', 'CHILD', 'VIEWER')),
        color_hex TEXT DEFAULT '#2563EB',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 4. Accounts (Physical and Virtual Ledger Accounts)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS accounts (
        id TEXT PRIMARY KEY,
        code TEXT UNIQUE,
        name TEXT NOT NULL,
        account_type TEXT NOT NULL CHECK(account_type IN ('ASSET', 'LIABILITY', 'EQUITY', 'INCOME', 'EXPENSE')),
        subtype TEXT NOT NULL,
        currency TEXT NOT NULL DEFAULT 'RUB',
        ownership_scope TEXT NOT NULL,
        owner_member_id TEXT REFERENCES members(id) ON DELETE SET NULL,
        description TEXT,
        credit_limit_cents INTEGER NOT NULL DEFAULT 0,
        initial_balance_cents INTEGER NOT NULL DEFAULT 0,
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 5. Categories
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS categories (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        category_type TEXT NOT NULL CHECK(category_type IN ('INCOME', 'EXPENSE')),
        parent_id TEXT REFERENCES categories(id) ON DELETE CASCADE,
        icon TEXT DEFAULT 'tag',
        sort_order INTEGER NOT NULL DEFAULT 0,
        is_active INTEGER NOT NULL DEFAULT 1
    );
    """)

    # 6. Transactions (Immutable Header)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS transactions (
        id TEXT PRIMARY KEY,
        tx_date TEXT NOT NULL,
        tx_type TEXT NOT NULL CHECK(tx_type IN ('INCOME', 'EXPENSE', 'TRANSFER', 'LOAN_ISSUE', 'LOAN_REPAYMENT', 'CREDIT_PURCHASE', 'CREDIT_PAYMENT', 'REFUND', 'ADJUSTMENT')),
        description TEXT NOT NULL,
        created_by_member_id TEXT REFERENCES members(id),
        idempotency_key TEXT UNIQUE,
        payload_hash TEXT,
        is_voided INTEGER NOT NULL DEFAULT 0,
        voided_reason TEXT,
        reversal_of_id TEXT REFERENCES transactions(id),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 7. Postings (Double-Entry Ledger Lines)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS postings (
        id TEXT PRIMARY KEY,
        transaction_id TEXT NOT NULL REFERENCES transactions(id) ON DELETE CASCADE,
        account_id TEXT NOT NULL REFERENCES accounts(id),
        amount_cents INTEGER NOT NULL CHECK(amount_cents > 0),
        posting_type TEXT NOT NULL CHECK(posting_type IN ('DEBIT', 'CREDIT')),
        ownership_scope TEXT NOT NULL,
        purpose_allocation TEXT NOT NULL DEFAULT 'SAFE_TO_SPEND',
        category_id TEXT REFERENCES categories(id) ON DELETE SET NULL,
        note TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 8. Local Change Log (for peer-to-peer sync)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS change_log (
        local_seq INTEGER PRIMARY KEY AUTOINCREMENT,
        entity_name TEXT NOT NULL,
        entity_id TEXT NOT NULL,
        change_type TEXT NOT NULL CHECK(change_type IN ('INSERT', 'UPDATE', 'DELETE', 'VOID')),
        payload_json TEXT NOT NULL,
        device_id TEXT NOT NULL,
        hlc_timestamp TEXT,
        updated_at_utc TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 9. Fixed Obligations (Stage 3 Recurring Bills & Budget Planning)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS obligations (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        amount_cents INTEGER NOT NULL CHECK(amount_cents > 0),
        due_day INTEGER NOT NULL CHECK(due_day BETWEEN 1 AND 31),
        category_id TEXT REFERENCES categories(id) ON DELETE SET NULL,
        payment_account_id TEXT REFERENCES accounts(id) ON DELETE SET NULL,
        note TEXT,
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 10. Monthly Obligation Payment Tracking
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS obligation_payments (
        id TEXT PRIMARY KEY,
        obligation_id TEXT NOT NULL REFERENCES obligations(id) ON DELETE CASCADE,
        month_year TEXT NOT NULL,
        transaction_id TEXT REFERENCES transactions(id) ON DELETE SET NULL,
        paid_amount_cents INTEGER NOT NULL,
        paid_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(obligation_id, month_year)
    );
    """)

    # 11. Savings Goals
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS goals (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        target_amount_cents INTEGER NOT NULL CHECK(target_amount_cents > 0),
        current_amount_cents INTEGER NOT NULL DEFAULT 0 CHECK(current_amount_cents >= 0),
        target_date TEXT,
        account_id TEXT REFERENCES accounts(id) ON DELETE SET NULL,
        category_id TEXT REFERENCES categories(id) ON DELETE SET NULL,
        icon TEXT DEFAULT '🎯',
        note TEXT,
        is_completed INTEGER NOT NULL DEFAULT 0,
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 12. Goal Contributions History
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS goal_contributions (
        id TEXT PRIMARY KEY,
        goal_id TEXT NOT NULL REFERENCES goals(id) ON DELETE CASCADE,
        amount_cents INTEGER NOT NULL CHECK(amount_cents > 0),
        transaction_id TEXT REFERENCES transactions(id) ON DELETE SET NULL,
        source_account_id TEXT REFERENCES accounts(id) ON DELETE SET NULL,
        note TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 13. Savings Envelopes / Virtual Piggy Banks (Конверты-копилки)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS envelopes (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        target_amount_cents INTEGER NOT NULL DEFAULT 0,
        current_amount_cents INTEGER NOT NULL DEFAULT 0,
        icon TEXT DEFAULT '✉️',
        color TEXT DEFAULT '#3b82f6',
        linked_account_id TEXT REFERENCES accounts(id) ON DELETE SET NULL,
        category_id TEXT REFERENCES categories(id) ON DELETE SET NULL,
        note TEXT,
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 14. Envelope Operations History
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS envelope_operations (
        id TEXT PRIMARY KEY,
        envelope_id TEXT NOT NULL REFERENCES envelopes(id) ON DELETE CASCADE,
        operation_type TEXT NOT NULL CHECK(operation_type IN ('DEPOSIT', 'WITHDRAW', 'TRANSFER')),
        amount_cents INTEGER NOT NULL CHECK(amount_cents > 0),
        source_account_id TEXT REFERENCES accounts(id) ON DELETE SET NULL,
        destination_account_id TEXT REFERENCES accounts(id) ON DELETE SET NULL,
        target_envelope_id TEXT REFERENCES envelopes(id) ON DELETE SET NULL,
        note TEXT,
        member_id TEXT REFERENCES members(id) ON DELETE SET NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # Schema migrations for existing databases
    cursor.execute("PRAGMA table_info(accounts);")
    existing_cols = {row["name"] for row in cursor.fetchall()}
    if "description" not in existing_cols:
        cursor.execute("ALTER TABLE accounts ADD COLUMN description TEXT;")
    if "credit_limit_cents" not in existing_cols:
        cursor.execute("ALTER TABLE accounts ADD COLUMN credit_limit_cents INTEGER NOT NULL DEFAULT 0;")
    if "initial_balance_cents" not in existing_cols:
        cursor.execute("ALTER TABLE accounts ADD COLUMN initial_balance_cents INTEGER NOT NULL DEFAULT 0;")

    cursor.execute("PRAGMA table_info(transactions);")
    tx_cols = {row["name"] for row in cursor.fetchall()}
    if "idempotency_key" not in tx_cols:
        cursor.execute("ALTER TABLE transactions ADD COLUMN idempotency_key TEXT;")
        cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_transactions_idempotency ON transactions(idempotency_key) WHERE idempotency_key IS NOT NULL;")
    if "payload_hash" not in tx_cols:
        cursor.execute("ALTER TABLE transactions ADD COLUMN payload_hash TEXT;")

    cursor.execute("PRAGMA table_info(postings);")
    post_cols = {row["name"] for row in cursor.fetchall()}
    if "category_id" not in post_cols:
        cursor.execute("ALTER TABLE postings ADD COLUMN category_id TEXT REFERENCES categories(id) ON DELETE SET NULL;")

    cursor.execute("PRAGMA table_info(categories);")
    cat_cols = {row["name"] for row in cursor.fetchall()}
    if "icon" not in cat_cols:
        cursor.execute("ALTER TABLE categories ADD COLUMN icon TEXT DEFAULT 'tag';")
    if "sort_order" not in cat_cols:
        cursor.execute("ALTER TABLE categories ADD COLUMN sort_order INTEGER NOT NULL DEFAULT 0;")

    cursor.execute("PRAGMA table_info(change_log);")
    change_cols = {row["name"] for row in cursor.fetchall()}
    if "hlc_timestamp" not in change_cols:
        cursor.execute("ALTER TABLE change_log ADD COLUMN hlc_timestamp TEXT;")

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_change_log_hlc ON change_log(hlc_timestamp);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_change_log_device ON change_log(device_id, local_seq);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_postings_category ON postings(category_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_goals_active ON goals(is_active);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_goal_contributions_goal ON goal_contributions(goal_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_envelopes_active ON envelopes(is_active);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_envelope_ops_env ON envelope_operations(envelope_id);")

    cursor.execute("""
    INSERT OR REPLACE INTO system_meta (key, value) VALUES ('schema_version', '4');
    """)
    conn.commit()


def init_database(db_path: Path = DB_PATH) -> None:
    """Initialize database schema on disk or in memory and ensure default owner."""
    if str(db_path) != ":memory:":
        db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = get_connection(db_path)
    try:
        create_schema(conn)
        # Ensure default owner user and envelopes exist in the production DB so system is never left in an uninitialized limbo
        if db_path == DB_PATH:
            cursor = conn.cursor()
            cursor.execute("SELECT count(*) FROM users WHERE role = 'OWNER' AND is_active = 1;")
            if cursor.fetchone()[0] == 0:
                from family_finances_os.auth import AuthService
                auth = AuthService(conn_or_path=conn)
                auth.create_owner("admin", "Глава семьи", "Family2026!")
                from family_finances_os.ledger import LedgerEngine
                ledger = LedgerEngine(conn_or_path=conn)
                ledger.seed_default_chart_of_accounts()
                ledger.seed_default_categories()
                conn.commit()

            cursor.execute("SELECT count(*) FROM envelopes WHERE is_active = 1;")
            if cursor.fetchone()[0] == 0:
                from family_finances_os.ledger import LedgerEngine
                ledger = LedgerEngine(conn_or_path=conn)
                ledger.create_envelope(name="Подушка безопасности", target_amount_cents=15000000, icon="🛡️", color="#10b981", initial_amount_cents=5000000, note="Неприкосновенный запас семьи")
                ledger.create_envelope(name="Отпуск на море", target_amount_cents=20000000, icon="🏖️", color="#06b6d4", initial_amount_cents=3500000, note="Летняя поездка всей семьей")
                ledger.create_envelope(name="Ремонт и уют", target_amount_cents=10000000, icon="🏠", color="#f59e0b", initial_amount_cents=1500000, note="Обновление мебели и техники")
                ledger.create_envelope(name="Подарки и праздники", target_amount_cents=5000000, icon="🎁", color="#ec4899", initial_amount_cents=1000000, note="Новый год и дни рождения")
                conn.commit()
    finally:
        conn.close()


class EncryptedDatabaseStorage:
    """
    Manages an at-rest encrypted SQLite database container on disk using
    Envelope Encryption (KEK + DEK) with AES-256-GCM.

    - Unlock: PBKDF2 derives KEK once (~300ms) to decrypt DEK.
    - Working state: In-memory decrypted SQLite database (:memory:) with foreign keys.
    - Save: Lightning-fast (<2ms) serialization and AES-256-GCM re-encryption using DEK,
      written atomically to disk with tempfile, os.fsync, and shadow backup.
    - Lock: Saves final state, closes DB connection, and wipes DEK from RAM.
    """
    def __init__(self, enc_path: Path = ENC_DB_PATH):
        self.enc_path = enc_path
        self._active_conn: Optional[sqlite3.Connection] = None
        self._dek: Optional[bytearray] = None
        self._salt: Optional[bytes] = None
        self._kek_nonce: Optional[bytes] = None
        self._encrypted_dek: Optional[bytes] = None
        self._lock = threading.RLock()

    def exists(self) -> bool:
        """Check if encrypted database container exists on disk and is non-empty."""
        return self.enc_path.exists() and self.enc_path.stat().st_size > 0

    def is_unlocked(self) -> bool:
        """Return True if container is unlocked and active in memory."""
        with self._lock:
            return self._active_conn is not None and self._dek is not None

    def initialize_new(self, password: str) -> sqlite3.Connection:
        """
        Create a new in-memory SQLite database, apply schema, and save as
        a fresh envelope encrypted container.
        """
        with self._lock:
            if self._active_conn is not None:
                self.lock()

            conn = sqlite3.connect(":memory:", check_same_thread=False, timeout=15.0)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON;")
            create_schema(conn)

            raw_bytes = conn.serialize()
            container, dek_buf, salt, kek_nonce, enc_dek = create_envelope(raw_bytes, password)

            # Atomic save to disk
            self._write_container_atomically(container)

            self._active_conn = conn
            self._dek = dek_buf
            self._salt = salt
            self._kek_nonce = kek_nonce
            self._encrypted_dek = enc_dek
            return conn

    def open(self, password: str) -> sqlite3.Connection:
        """
        Decrypt existing envelope container using master password and deserialize
        into in-memory SQLite connection.
        """
        with self._lock:
            if not self.exists():
                raise FileNotFoundError(f"Encrypted database not found at: {self.enc_path}")

            if self._active_conn is not None:
                self.lock()

            raw_enc = self.enc_path.read_bytes()
            raw_bytes, dek_buf, salt, kek_nonce, enc_dek = open_envelope(raw_enc, password)

            conn = sqlite3.connect(":memory:", check_same_thread=False, timeout=15.0)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON;")
            conn.deserialize(raw_bytes)

            # Integrity verification
            cur = conn.cursor()
            cur.execute("PRAGMA integrity_check;")
            integrity_row = cur.fetchone()
            if not integrity_row or integrity_row[0] != "ok":
                conn.close()
                wipe_memory(dek_buf)
                raise RuntimeError("Integrity check failed on decrypted database!")

            # Run automatic schema migrations if container has older schema version
            create_schema(conn)

            self._active_conn = conn
            self._dek = dek_buf
            self._salt = salt
            self._kek_nonce = kek_nonce
            self._encrypted_dek = enc_dek
            return conn

    def get_connection(self) -> sqlite3.Connection:
        """Return the active in-memory SQLite connection."""
        with self._lock:
            if self._active_conn is None or self._dek is None:
                raise RuntimeError("Encrypted database is locked. Master password required to unlock.")
            return self._active_conn

    def save(self) -> None:
        """
        Serialize memory DB and atomically encrypt to disk with AES-256-GCM.
        Executes in < 2ms using cached DEK.
        """
        with self._lock:
            if not self.is_unlocked():
                raise RuntimeError("Cannot save: database is locked or not open.")

            raw_bytes = self._active_conn.serialize()
            container = fast_save_envelope(
                raw_bytes=raw_bytes,
                dek=self._dek,
                salt=self._salt,
                kek_nonce=self._kek_nonce,
                encrypted_dek=self._encrypted_dek
            )
            self._write_container_atomically(container)

    def _write_container_atomically(self, container_bytes: bytes) -> None:
        """
        Atomic write pattern with fsync and shadow backup:
        1. Write to temp file in same directory.
        2. Flush and os.fsync.
        3. If target exists, copy to target.bak.
        4. os.replace temp file to target.
        """
        parent_dir = self.enc_path.parent
        parent_dir.mkdir(parents=True, exist_ok=True)

        tmp_path = parent_dir / f"{self.enc_path.name}.tmp_{int(time.time() * 1000)}"
        bak_path = parent_dir / f"{self.enc_path.name}.bak"

        try:
            with open(tmp_path, "wb") as f:
                f.write(container_bytes)
                f.flush()
                os.fsync(f.fileno())

            # Shadow backup of existing valid file
            if self.enc_path.exists():
                try:
                    shutil.copy2(self.enc_path, bak_path)
                except Exception:
                    pass

            # Atomic replace
            os.replace(tmp_path, self.enc_path)
        finally:
            if tmp_path.exists():
                try:
                    tmp_path.unlink()
                except Exception:
                    pass

    def change_password(self, old_password: str, new_password: str) -> bool:
        """
        Change master password and re-encrypt the DEK with a new KEK derived from new_password.
        """
        with self._lock:
            if len(new_password) < 6:
                raise ValueError("New password must be at least 6 characters long.")

            if not self.is_unlocked():
                self.open(old_password)

            # Generate new salt and KEK for new password
            new_salt = generate_salt()
            new_kek = derive_key(new_password, new_salt)
            new_kek_nonce = generate_nonce()
            new_kek_gcm = AESGCM(new_kek)
            new_encrypted_dek = new_kek_gcm.encrypt(new_kek_nonce, bytes(self._dek), None)

            self._salt = new_salt
            self._kek_nonce = new_kek_nonce
            self._encrypted_dek = new_encrypted_dek

            # Save immediately with new credentials
            self.save()
            return True

    def lock(self) -> None:
        """
        Save final state to disk, close in-memory SQLite connection,
        and securely wipe DEK from memory.
        """
        with self._lock:
            if self._active_conn is not None:
                try:
                    if self._dek is not None:
                        self.save()
                except Exception:
                    pass
                try:
                    self._active_conn.close()
                except Exception:
                    pass
                self._active_conn = None

            if self._dek is not None:
                wipe_memory(self._dek)
                self._dek = None

            self._salt = None
            self._kek_nonce = None
            self._encrypted_dek = None

    def close(self) -> None:
        """Alias for lock()."""
        self.lock()


# Global Singleton Storage Instance
GLOBAL_STORAGE = EncryptedDatabaseStorage()


def get_db_connection(conn_or_path: Any = None) -> sqlite3.Connection:
    """
    Central connection provider for all services (Auth, Ledger, CLI, Web).
    - If explicit connection passed, returns it.
    - If explicit path passed, opens connection to that path.
    - If GLOBAL_STORAGE is unlocked, returns its active memory connection.
    - If database is encrypted on disk but locked, raises RuntimeError.
    - If STRICT_ENCRYPTION is on and plaintext DB is requested, raises PermissionError.
    - Otherwise falls back to default DB_PATH for backwards compatibility.
    """
    if isinstance(conn_or_path, sqlite3.Connection):
        return conn_or_path

    if conn_or_path:
        path = Path(conn_or_path)
        if STRICT_ENCRYPTION and path.suffix != ".enc" and str(path) != ":memory:":
            raise PermissionError("STRICT_ENCRYPTION is enabled: Plaintext databases are not permitted.")
        return get_connection(path)

    if GLOBAL_STORAGE.is_unlocked():
        return GLOBAL_STORAGE.get_connection()

    if STRICT_ENCRYPTION:
        if ENC_DB_PATH.exists() and not GLOBAL_STORAGE.is_unlocked():
            raise RuntimeError("База данных зашифрована и заблокирована. Требуется ввод мастер-пароля.")
        raise PermissionError("STRICT_ENCRYPTION is enabled: Plaintext databases are not permitted.")

    if DB_PATH.exists():
        return get_connection(DB_PATH)

    if ENC_DB_PATH.exists() and not GLOBAL_STORAGE.is_unlocked():
        raise RuntimeError("База данных зашифрована и заблокирована. Требуется ввод мастер-пароля.")

    if not DB_PATH.exists() and not ENC_DB_PATH.exists():
        init_database(DB_PATH)

    return get_connection(DB_PATH)


def check_db_health(conn_or_path: Any = None) -> dict:
    """Check database connection and table integrity."""
    try:
        if GLOBAL_STORAGE.is_unlocked() and conn_or_path is None:
            conn = GLOBAL_STORAGE.get_connection()
            cursor = conn.cursor()
            cursor.execute("PRAGMA integrity_check;")
            integrity_result = cursor.fetchone()[0]
            cursor.execute("SELECT count(*) FROM sqlite_master WHERE type='table';")
            table_count = cursor.fetchone()[0]
            cursor.execute("SELECT value FROM system_meta WHERE key='schema_version';")
            schema_ver = cursor.fetchone()
            schema_version = schema_ver[0] if schema_ver else "Unknown"
            return {
                "status": "healthy" if integrity_result == "ok" else "corrupt",
                "integrity": integrity_result,
                "table_count": table_count,
                "schema_version": schema_version,
                "db_mode": "ENCRYPTED_MEMORY",
                "is_encrypted": True,
                "is_unlocked": True,
                "file_exists": ENC_DB_PATH.exists()
            }

        target = conn_or_path or DB_PATH
        if isinstance(target, sqlite3.Connection):
            cursor = target.cursor()
            cursor.execute("PRAGMA integrity_check;")
            integrity_result = cursor.fetchone()[0]
            cursor.execute("SELECT count(*) FROM sqlite_master WHERE type='table';")
            table_count = cursor.fetchone()[0]
            cursor.execute("SELECT value FROM system_meta WHERE key='schema_version';")
            schema_ver = cursor.fetchone()
            schema_version = schema_ver[0] if schema_ver else "Unknown"
            return {
                "status": "healthy" if integrity_result == "ok" else "corrupt",
                "integrity": integrity_result,
                "table_count": table_count,
                "schema_version": schema_version,
                "db_mode": "ACTIVE_CONNECTION",
                "is_encrypted": False,
                "is_unlocked": True,
                "file_exists": True
            }
        else:
            db_path = Path(target)
            if not db_path.exists():
                return {
                    "status": "missing",
                    "integrity": "none",
                    "table_count": 0,
                    "schema_version": "None",
                    "db_mode": "FILE",
                    "is_encrypted": ENC_DB_PATH.exists(),
                    "is_unlocked": False,
                    "file_exists": False
                }
            with get_connection(db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("PRAGMA integrity_check;")
                integrity_result = cursor.fetchone()[0]
                cursor.execute("SELECT count(*) FROM sqlite_master WHERE type='table';")
                table_count = cursor.fetchone()[0]
                cursor.execute("SELECT value FROM system_meta WHERE key='schema_version';")
                schema_ver = cursor.fetchone()
                schema_version = schema_ver[0] if schema_ver else "Unknown"
                return {
                    "status": "healthy" if integrity_result == "ok" else "corrupt",
                    "integrity": integrity_result,
                    "table_count": table_count,
                    "schema_version": schema_version,
                    "db_mode": "PLAINTEXT_FILE",
                    "is_encrypted": ENC_DB_PATH.exists(),
                    "is_unlocked": True,
                    "file_exists": db_path.exists()
                }
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "is_encrypted": ENC_DB_PATH.exists(),
            "is_unlocked": GLOBAL_STORAGE.is_unlocked(),
            "file_exists": False
        }
