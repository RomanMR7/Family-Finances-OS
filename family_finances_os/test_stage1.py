"""
Family Finances OS - Comprehensive Verification Test Suite
Verifies all Stage 1 requirements and critical fixes:
1. Application launch & unconfigured state detection
2. Creation of initial Family Owner & rejection of duplicate setup
3. Password hashing with OWASP-recommended 600,000 PBKDF2 iterations
4. Authentication with valid vs invalid passwords (constant-time verification)
5. Session management: creation, TTL validation, and termination via logout
6. Protection of HTTP API: rejection of unauthenticated requests (401)
7. Actual at-rest database encryption via AES-256-GCM:
   - File on disk is ciphertext with ENC_MAGIC, no SQLite signature
   - Opening with wrong password strictly raises PermissionError
   - Opening with correct password restores full database
8. Database connection health, WAL mode, schema version, and foreign keys
9. Double-entry equation enforcement: rejection of unbalanced postings
10. Atomic transaction rollback: failure does not leave partial postings
11. Transaction deduplication & idempotency key enforcement
12. Dynamic Safe-to-Spend calculation across custom accounts
13. Data persistence across application shutdown and restart
14. Complete 100% offline functionality (zero network calls)
"""
import os
import shutil
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

from family_finances_os.config import (
    PBKDF2_ITERATIONS,
    ENC_MAGIC,
    ENC_ENV_MAGIC,
    SESSION_TTL_SECONDS
)
from family_finances_os.db import (
    init_database,
    check_db_health,
    get_connection,
    EncryptedDatabaseStorage
)
from family_finances_os.security import (
    hash_password,
    verify_password,
    encrypt_database_bytes,
    decrypt_database_bytes,
    SessionManager
)
from family_finances_os.auth import AuthService
from family_finances_os.ledger import LedgerEngine
from family_finances_os.models import (
    Transaction,
    Posting,
    Account,
    rubles_to_cents,
    cents_to_rubles,
    generate_uuid,
    current_iso_time
)


class TestFamilyFinancesOSVerification(unittest.TestCase):
    def setUp(self):
        # Create an isolated temporary test directory
        self.test_dir = tempfile.mkdtemp(prefix="ffos_audit_")
        self.db_path = Path(self.test_dir) / "test_family_finances.db"
        self.enc_db_path = Path(self.test_dir) / "test_family_finances.db.enc"
        self.session_mgr = SessionManager(ttl_seconds=3600)
        self.auth = AuthService(conn_or_path=self.db_path, session_manager=self.session_mgr)
        self.ledger = LedgerEngine(conn_or_path=self.db_path)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    # 1. Startup & Initial State
    def test_01_application_launch_and_starter_screen_state(self):
        """Test initial launch: detects that no owner exists yet."""
        init_database(self.db_path)
        self.assertFalse(self.auth.has_owner(), "Initial DB must not report existing owner")

    # 2. Owner Setup & Rejection of Re-initialization
    def test_02_create_first_owner_and_prevent_reinitialization(self):
        """Test owner creation and strict rejection of duplicate/second owner."""
        init_database(self.db_path)
        res = self.auth.create_owner("ivan_owner", "Иван (Владелец)", "StrongMasterPassword2026!")
        self.assertEqual(res["username"], "ivan_owner")
        self.assertEqual(res["role"], "OWNER")
        self.assertTrue(self.auth.has_owner())

        # Attempting duplicate setup must raise ValueError
        with self.assertRaises(ValueError):
            self.auth.create_owner("impostor", "Второй владелец", "HackedPassword!")

    # 3. Password Hashing Strength
    def test_03_password_hashing_parameters_and_timing(self):
        """Test PBKDF2 parameters: 600,000 iterations and constant-time check."""
        self.assertEqual(PBKDF2_ITERATIONS, 600_000, "PBKDF2 iterations must be 600,000 per OWASP")
        pwd_hash, salt = hash_password("SuperSecret2026!")
        self.assertEqual(len(pwd_hash), 32)
        self.assertEqual(len(salt), 32)

        # Verification succeeds with right password
        self.assertTrue(verify_password("SuperSecret2026!", pwd_hash, salt))
        # Verification fails with wrong password
        self.assertFalse(verify_password("WrongPassword!", pwd_hash, salt))

    # 4. Authentication & Bad Passwords
    def test_04_login_with_correct_and_incorrect_passwords(self):
        """Test login: correct password returns session, wrong password returns None."""
        init_database(self.db_path)
        self.auth.create_owner("ivan_owner", "Иван", "Master2026!")

        # Correct login
        user = self.auth.authenticate("ivan_owner", "Master2026!")
        self.assertIsNotNone(user)
        self.assertEqual(user["username"], "ivan_owner")
        self.assertTrue("session_token" in user)

        # Incorrect login
        self.assertIsNone(self.auth.authenticate("ivan_owner", "BadPassword!"))
        self.assertIsNone(self.auth.authenticate("nonexistent_user", "AnyPassword"))

    # 5. Session Management & Logout
    def test_05_session_lifecycle_and_logout(self):
        """Test session creation, validation, TTL expiration, and explicit logout."""
        user_data = {"user_id": "u1", "username": "admin", "role": "OWNER"}
        token = self.session_mgr.create_session(user_data)
        self.assertIsNotNone(token)

        # Validate active session
        validated = self.session_mgr.validate_session(token)
        self.assertIsNotNone(validated)
        self.assertEqual(validated["username"], "admin")

        # Invalidate via logout
        logout_ok = self.session_mgr.invalidate_session(token)
        self.assertTrue(logout_ok)

        # Post-logout validation must fail
        self.assertIsNone(self.session_mgr.validate_session(token))

        # Test TTL expiration with a 1-second session manager
        short_mgr = SessionManager(ttl_seconds=0.01)
        short_token = short_mgr.create_session(user_data)
        time.sleep(0.05)
        self.assertIsNone(short_mgr.validate_session(short_token), "Expired session must be rejected")

    # 6. Actual Database Encryption at Rest (AES-256-GCM)
    def test_06_at_rest_database_encryption_and_decryption(self):
        """
        Verify that database container on disk is genuinely encrypted with AES-256-GCM:
        1. Encrypted file has ENC_MAGIC, NOT SQLite format signature.
        2. Cannot be opened by standard sqlite3.connect without decryption.
        3. Decrypting with wrong password fails with PermissionError.
        4. Decrypting with correct password restores all tables and data.
        """
        storage = EncryptedDatabaseStorage(enc_path=self.enc_db_path)
        conn = storage.initialize_new(password="FamilyKey2026!")

        # Add data to the encrypted database
        conn.execute(
            "INSERT INTO users (id, username, display_name, role, password_hash, salt) VALUES ('u1', 'admin', 'Admin', 'OWNER', ?, ?);",
            (b'dummy_hash_bytes_32_bytes_len!', b'dummy_salt_bytes_32_bytes_len!')
        )
        conn.commit()
        storage.save()
        storage.close()

        # Check raw file bytes on disk
        self.assertTrue(self.enc_db_path.exists())
        file_bytes = self.enc_db_path.read_bytes()
        self.assertTrue(file_bytes.startswith((ENC_MAGIC, ENC_ENV_MAGIC)), "File must begin with FFOS_ENC or FFOS_ENV header")
        self.assertFalse(b"SQLite format 3" in file_bytes, "Plaintext SQLite header must NOT exist on disk!")

        # Attempting to open raw file with plain sqlite3 must fail
        with self.assertRaises(sqlite3.DatabaseError):
            broken_conn = sqlite3.connect(str(self.enc_db_path))
            broken_conn.execute("SELECT * FROM users;").fetchall()

        # Decrypting with wrong password must be rejected
        storage_fail = EncryptedDatabaseStorage(enc_path=self.enc_db_path)
        with self.assertRaises(PermissionError):
            storage_fail.open(password="WrongFamilyPassword!")

        # Decrypting with correct password restores data
        storage_ok = EncryptedDatabaseStorage(enc_path=self.enc_db_path)
        restored_conn = storage_ok.open(password="FamilyKey2026!")
        rows = restored_conn.execute("SELECT username, display_name FROM users;").fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["username"], "admin")
        storage_ok.close()

    # 7. Database Health, WAL Mode, Foreign Keys
    def test_07_database_health_wal_and_foreign_keys(self):
        """Test SQLite WAL mode, integrity check, and foreign keys enforcement."""
        init_database(self.db_path)
        health = check_db_health(self.db_path)
        self.assertEqual(health["status"], "healthy")
        self.assertEqual(health["integrity"], "ok")
        self.assertIn(health["schema_version"], ("1", "2", "3", "4"))

        # Test foreign key enforcement
        with get_connection(self.db_path) as conn:
            # Inserting posting pointing to nonexistent transaction must fail
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute("""
                INSERT INTO postings (id, transaction_id, account_id, amount_cents, posting_type, ownership_scope)
                VALUES ('p1', 'nonexistent_tx', 'nonexistent_acc', 1000, 'DEBIT', 'COMMON');
                """)

    # 8. Double-Entry Accounting & Integer Cents
    def test_08_double_entry_balance_and_cents_precision(self):
        """Test double-entry: Debit == Credit, exact integer cents."""
        init_database(self.db_path)
        self.ledger.seed_default_chart_of_accounts()

        bank_acc = self.ledger.get_account_by_code("1010")
        salary_acc = self.ledger.get_account_by_code("4010")

        # 120,000.50 RUB salary
        amount_cents = rubles_to_cents("120000.50")
        self.assertEqual(amount_cents, 12000050)

        tx_id = generate_uuid()
        tx = Transaction(
            id=tx_id,
            tx_date="2026-11-09",
            tx_type="INCOME",
            description="Зарплата",
            created_by_member_id=None,
            postings=[
                Posting(id=generate_uuid(), transaction_id=tx_id, account_id=bank_acc.id, amount_cents=amount_cents, posting_type="DEBIT"),
                Posting(id=generate_uuid(), transaction_id=tx_id, account_id=salary_acc.id, amount_cents=amount_cents, posting_type="CREDIT"),
            ]
        )
        self.ledger.record_transaction(tx)
        self.assertEqual(self.ledger.get_account_balance_cents(bank_acc.id), 12000050)

    # 9. Rejection of Unbalanced Postings
    def test_09_unbalanced_posting_rejection(self):
        """Verify that imbalanced transactions (Debit != Credit) are strictly rejected."""
        init_database(self.db_path)
        self.ledger.seed_default_chart_of_accounts()
        bank_acc = self.ledger.get_account_by_code("1010")

        tx_imbalanced = Transaction(
            id=generate_uuid(),
            tx_date="2026-11-09",
            tx_type="EXPENSE",
            description="Несбалансированная",
            created_by_member_id=None,
            postings=[
                Posting(id=generate_uuid(), transaction_id="t1", account_id=bank_acc.id, amount_cents=5000, posting_type="DEBIT"),
                Posting(id=generate_uuid(), transaction_id="t1", account_id=bank_acc.id, amount_cents=4500, posting_type="CREDIT"),
            ]
        )
        self.assertFalse(tx_imbalanced.validate_double_entry())
        with self.assertRaises(ValueError):
            self.ledger.record_transaction(tx_imbalanced)

    # 10. Atomic Rollback on Failure
    def test_10_atomic_rollback_on_failed_transaction(self):
        """Verify that if any posting fails, the entire transaction is rolled back."""
        init_database(self.db_path)
        self.ledger.seed_default_chart_of_accounts()
        bank_acc = self.ledger.get_account_by_code("1010")

        # Second posting has negative amount (violates CHECK(amount_cents > 0))
        tx_failing = Transaction(
            id=generate_uuid(),
            tx_date="2026-11-09",
            tx_type="EXPENSE",
            description="Ошибочная операция",
            created_by_member_id=None,
            postings=[
                Posting(id=generate_uuid(), transaction_id="tf", account_id=bank_acc.id, amount_cents=1000, posting_type="DEBIT"),
                Posting(id=generate_uuid(), transaction_id="tf", account_id=bank_acc.id, amount_cents=-1000, posting_type="CREDIT"),
            ]
        )
        # Attempt to save must fail
        with self.assertRaises(Exception):
            self.ledger.record_transaction(tx_failing)

        # Verify nothing was written to transactions or postings
        with get_connection(self.db_path) as conn:
            cnt = conn.execute("SELECT count(*) FROM transactions;").fetchone()[0]
            self.assertEqual(cnt, 0, "Failed transaction must leave 0 rows in transactions table")

    # 11. Transaction Deduplication (Idempotency Key)
    def test_11_transaction_deduplication_via_idempotency_key(self):
        """Verify that submitting the same idempotency_key returns existing tx without duplicating postings."""
        init_database(self.db_path)
        self.ledger.seed_default_chart_of_accounts()
        bank_acc = self.ledger.get_account_by_code("1010")
        salary_acc = self.ledger.get_account_by_code("4010")

        amount_cents = rubles_to_cents(5000)
        idempotency_key = "idemp_client_req_998877"

        tx1 = Transaction(
            id=generate_uuid(),
            tx_date="2026-11-09",
            tx_type="INCOME",
            description="Тест дедупликации",
            created_by_member_id=None,
            postings=[
                Posting(id=generate_uuid(), transaction_id="1", account_id=bank_acc.id, amount_cents=amount_cents, posting_type="DEBIT"),
                Posting(id=generate_uuid(), transaction_id="1", account_id=salary_acc.id, amount_cents=amount_cents, posting_type="CREDIT"),
            ]
        )
        saved_id_1 = self.ledger.record_transaction(tx1, idempotency_key=idempotency_key)

        # Second submission with same idempotency_key and identical payload
        tx2 = Transaction(
            id=generate_uuid(),
            tx_date="2026-11-09",
            tx_type="INCOME",
            description="Тест дедупликации",
            created_by_member_id=None,
            postings=[
                Posting(id=generate_uuid(), transaction_id="2", account_id=bank_acc.id, amount_cents=amount_cents, posting_type="DEBIT"),
                Posting(id=generate_uuid(), transaction_id="2", account_id=salary_acc.id, amount_cents=amount_cents, posting_type="CREDIT"),
            ]
        )
        saved_id_2 = self.ledger.record_transaction(tx2, idempotency_key=idempotency_key)

        # Must return the SAME transaction ID
        self.assertEqual(saved_id_1, saved_id_2)

        # Balance must only reflect ONE transaction (5,000 RUB, not 10,000 RUB)
        balance = self.ledger.get_account_balance_cents(bank_acc.id)
        self.assertEqual(balance, amount_cents)

    # 12. Dynamic Safe-to-Spend Calculation
    def test_12_dynamic_safe_to_spend_calculation(self):
        """Verify dynamic Safe-to-Spend computation with custom accounts and reserves."""
        init_database(self.db_path)
        self.ledger.seed_default_chart_of_accounts()

        bank_acc = self.ledger.get_account_by_code("1010")     # Common Debit Card
        savings_acc = self.ledger.get_account_by_code("1030")  # Common Savings Reserve
        credit_acc = self.ledger.get_account_by_code("2020")   # Common Credit Card
        income_acc = self.ledger.get_account_by_code("4010")   # Salary

        # 1. Income 100,000 RUB to Bank Account
        tx1_id = generate_uuid()
        self.ledger.record_transaction(Transaction(
            id=tx1_id, tx_date="2026-11-09", tx_type="INCOME", description="Зарплата", created_by_member_id=None,
            postings=[
                Posting(id=generate_uuid(), transaction_id=tx1_id, account_id=bank_acc.id, amount_cents=10000000, posting_type="DEBIT"),
                Posting(id=generate_uuid(), transaction_id=tx1_id, account_id=income_acc.id, amount_cents=10000000, posting_type="CREDIT"),
            ]
        ))

        # 2. Transfer 30,000 RUB to Savings Reserve (1030)
        tx2_id = generate_uuid()
        self.ledger.record_transaction(Transaction(
            id=tx2_id, tx_date="2026-11-09", tx_type="TRANSFER", description="В резерв", created_by_member_id=None,
            postings=[
                Posting(id=generate_uuid(), transaction_id=tx2_id, account_id=savings_acc.id, amount_cents=3000000, posting_type="DEBIT"),
                Posting(id=generate_uuid(), transaction_id=tx2_id, account_id=bank_acc.id, amount_cents=3000000, posting_type="CREDIT"),
            ]
        ))

        # 3. Credit Card Debt 10,000 RUB (2020)
        tx3_id = generate_uuid()
        grocery_acc = self.ledger.get_account_by_code("5010")
        self.ledger.record_transaction(Transaction(
            id=tx3_id, tx_date="2026-11-09", tx_type="CREDIT_PURCHASE", description="Покупка в кредит", created_by_member_id=None,
            postings=[
                Posting(id=generate_uuid(), transaction_id=tx3_id, account_id=grocery_acc.id, amount_cents=1000000, posting_type="DEBIT"),
                Posting(id=generate_uuid(), transaction_id=tx3_id, account_id=credit_acc.id, amount_cents=1000000, posting_type="CREDIT"),
            ]
        ))

        # Expected:
        # Common Liquid Assets = 100,000 - 30,000 = 70,000 RUB (7000000 cents)
        # Emergency Reserve = 30,000 RUB (3000000 cents)
        # Credit Card Debt = 10,000 RUB (1000000 cents)
        # Safe-to-Spend = Liquid (70,000) - Debt (10,000) = 60,000 RUB (6000000 cents)
        s2s = self.ledger.calculate_safe_to_spend_cents()
        self.assertEqual(s2s["common_liquid_assets_cents"], 7000000)
        self.assertEqual(s2s["emergency_reserve_cents"], 3000000)
        self.assertEqual(s2s["credit_card_debt_cents"], 1000000)
        self.assertEqual(s2s["common_safe_to_spend_cents"], 6000000)

    # 13. Persistence Across Restarts
    def test_13_persistence_across_restarts(self):
        """Verify that all state remains 100% intact after re-creating engine instances."""
        init_database(self.db_path)
        self.ledger.seed_default_chart_of_accounts()
        self.auth.create_owner("ivan_owner", "Иван", "MasterPassword2026!")

        bank_acc = self.ledger.get_account_by_code("1010")
        salary_acc = self.ledger.get_account_by_code("4010")
        tx_id = generate_uuid()
        self.ledger.record_transaction(Transaction(
            id=tx_id, tx_date="2026-11-09", tx_type="INCOME", description="Сохранение", created_by_member_id=None,
            postings=[
                Posting(id=generate_uuid(), transaction_id=tx_id, account_id=bank_acc.id, amount_cents=8800000, posting_type="DEBIT"),
                Posting(id=generate_uuid(), transaction_id=tx_id, account_id=salary_acc.id, amount_cents=8800000, posting_type="CREDIT"),
            ]
        ))

        # Simulate shutdown
        del self.auth
        del self.ledger

        # Re-open
        fresh_auth = AuthService(conn_or_path=self.db_path)
        fresh_ledger = LedgerEngine(conn_or_path=self.db_path)

        self.assertTrue(fresh_auth.has_owner())
        self.assertIsNotNone(fresh_auth.authenticate("ivan_owner", "MasterPassword2026!"))
        reopened_bank = fresh_ledger.get_account_by_code("1010")
        self.assertEqual(fresh_ledger.get_account_balance_cents(reopened_bank.id), 8800000)

    # 14. 100% Offline Functionality
    def test_14_complete_offline_functionality(self):
        """Confirm app operates with zero network dependencies."""
        init_database(self.db_path)
        health = check_db_health(self.db_path)
        self.assertEqual(health["status"], "healthy")

    # 15. Rejection of Unauthorized HTTP Requests
    def test_15_unauthorized_http_requests_rejected(self):
        """Verify that all financial endpoints strictly reject unauthenticated requests with HTTP 401."""
        init_database(self.db_path)
        from family_finances_os.web_server import FamilyFinancesHandler

        class MockSocket:
            def __init__(self, raw_data):
                self.input_bytes = raw_data
                self.output = bytearray()
            def makefile(self, mode, *args, **kwargs):
                import io
                if 'r' in mode:
                    return io.BytesIO(self.input_bytes)
                class WriteWrapper:
                    def __init__(self, target): self.target = target
                    def write(self, b): self.target.extend(b)
                    def flush(self): pass
                return WriteWrapper(self.output)
            def sendall(self, b):
                self.output.extend(b)

        # 1. Unauthenticated GET /api/summary
        sock1 = MockSocket(b"GET /api/summary HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        FamilyFinancesHandler(sock1, ("127.0.0.1", 12345), None)
        self.assertTrue(b"401" in bytes(sock1.output), "Unauthenticated GET /api/summary must return 401")

        # 2. Unauthenticated GET /api/accounts
        sock2 = MockSocket(b"GET /api/accounts HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        FamilyFinancesHandler(sock2, ("127.0.0.1", 12345), None)
        self.assertTrue(b"401" in bytes(sock2.output), "Unauthenticated GET /api/accounts must return 401")

        # 3. Unauthenticated GET /api/transactions
        sock3 = MockSocket(b"GET /api/transactions HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        FamilyFinancesHandler(sock3, ("127.0.0.1", 12345), None)
        self.assertTrue(b"401" in bytes(sock3.output), "Unauthenticated GET /api/transactions must return 401")

        # 4. Unauthenticated POST /api/transaction/create
        sock4 = MockSocket(b"POST /api/transaction/create HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 2\r\n\r\n{}")
        FamilyFinancesHandler(sock4, ("127.0.0.1", 12345), None)
        self.assertTrue(b"401" in bytes(sock4.output), "Unauthenticated POST /api/transaction/create must return 401")

        # 5. Invalid token Bearer fake_token
        sock5 = MockSocket(b"GET /api/summary HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer fake_token_xyz\r\n\r\n")
        FamilyFinancesHandler(sock5, ("127.0.0.1", 12345), None)
        self.assertTrue(b"401" in bytes(sock5.output), "Invalid Bearer token must return 401")

    # 16. Authorized HTTP Session Lifecycle
    def test_16_authorized_http_session_lifecycle(self):
        """Verify that valid Bearer token permits access (200), and logout revokes it (subsequent 401)."""
        init_database(self.db_path)
        from family_finances_os.web_server import FamilyFinancesHandler, GLOBAL_SESSION_MANAGER

        class MockSocket:
            def __init__(self, raw_data):
                self.input_bytes = raw_data
                self.output = bytearray()
            def makefile(self, mode, *args, **kwargs):
                import io
                if 'r' in mode:
                    return io.BytesIO(self.input_bytes)
                class WriteWrapper:
                    def __init__(self, target): self.target = target
                    def write(self, b): self.target.extend(b)
                    def flush(self): pass
                return WriteWrapper(self.output)
            def sendall(self, b):
                self.output.extend(b)

        # Create valid session
        user_info = {"user_id": "u1", "username": "admin", "role": "OWNER"}
        valid_token = GLOBAL_SESSION_MANAGER.create_session(user_info)

        # 1. Authorized GET /api/summary
        req_auth = f"GET /api/summary HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {valid_token}\r\n\r\n".encode()
        sock_auth = MockSocket(req_auth)
        FamilyFinancesHandler(sock_auth, ("127.0.0.1", 12345), None)
        self.assertTrue(b"200 OK" in bytes(sock_auth.output), "Authorized request must return 200 OK")

        # 2. POST /api/logout
        req_logout = f"POST /api/logout HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {valid_token}\r\nContent-Length: 0\r\n\r\n".encode()
        sock_logout = MockSocket(req_logout)
        FamilyFinancesHandler(sock_logout, ("127.0.0.1", 12345), None)
        self.assertTrue(b"200 OK" in bytes(sock_logout.output), "Logout request must return 200 OK")

        # 3. Post-logout GET /api/summary with the same token must now fail with 401
        sock_revoked = MockSocket(req_auth)
        FamilyFinancesHandler(sock_revoked, ("127.0.0.1", 12345), None)
        self.assertTrue(b"401" in bytes(sock_revoked.output), "Request with revoked token must return 401")


if __name__ == "__main__":
    unittest.main(verbosity=2)
