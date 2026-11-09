"""
Family Finances OS - Envelope Encryption & Security Hardening Test Suite
Verifies:
1. Envelope container format (FFOS_ENV\x01) with KEK (PBKDF2 600k) + DEK (AES-256-GCM).
2. Lightning-fast saves (< 25ms) using in-memory DEK without repeated PBKDF2.
3. Atomic file persistence, shadow backup (.enc.bak), and os.fsync.
4. RAM key wiping on lock / close (wipe_memory).
5. Wrong password & cryptographic tampering rejection (InvalidTag / PermissionError).
6. Master password rotation without full database re-encryption.
7. Web server DNS-rebinding protection and security headers (CSP, nosniff, DENY).
8. Web server locked gatekeeper (423 Locked) and unlock lifecycle (/api/unlock, /api/lock).
"""
import io
import os
import shutil
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

from family_finances_os.config import (
    ENC_ENV_MAGIC,
    ENC_MAGIC,
    DEK_SIZE,
    ENCRYPTED_DEK_SIZE
)
from family_finances_os.security import (
    create_envelope,
    open_envelope,
    fast_save_envelope,
    change_envelope_password,
    wipe_memory,
    generate_salt
)
from family_finances_os.db import (
    EncryptedDatabaseStorage,
    init_database,
    create_schema,
    get_connection,
    check_db_health
)
from family_finances_os.web_server import FamilyFinancesHandler, GLOBAL_SESSION_MANAGER


class MockSocket:
    def __init__(self, input_bytes: bytes):
        self.input_bytes = input_bytes
        self.output = bytearray()

    def makefile(self, mode, *args, **kwargs):
        if 'r' in mode:
            return io.BytesIO(self.input_bytes)
        class WriteWrapper:
            def __init__(self, target): self.target = target
            def write(self, b): self.target.extend(b)
            def flush(self): pass
        return WriteWrapper(self.output)

    def sendall(self, b):
        self.output.extend(b)


class TestEnvelopeSecurity(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="ffos_sec_")
        self.enc_path = Path(self.test_dir) / "test_family.db.enc"
        self.storage = EncryptedDatabaseStorage(self.enc_path)

    def tearDown(self):
        if self.storage.is_unlocked():
            self.storage.lock()
        shutil.rmtree(self.test_dir, ignore_errors=True)

    # 1. Envelope Format & Header Layout
    def test_01_envelope_format_and_header(self):
        """Verify container header structure: Magic (9B), Salt (32B), KEK Nonce (12B), Encrypted DEK (48B), DB Nonce (12B)."""
        raw_db = b"SQLite format 3\x00" + b"A" * 1024
        container, dek, salt, kek_nonce, enc_dek = create_envelope(raw_db, "MasterKey123!")

        self.assertTrue(container.startswith(ENC_ENV_MAGIC))
        self.assertEqual(len(dek), DEK_SIZE)
        self.assertEqual(len(salt), 32)
        self.assertEqual(len(kek_nonce), 12)
        self.assertEqual(len(enc_dek), ENCRYPTED_DEK_SIZE)

        # Open and verify payload
        dec_bytes, dec_dek, _, _, _ = open_envelope(container, "MasterKey123!")
        self.assertEqual(dec_bytes, raw_db)
        self.assertEqual(dec_dek, dek)

    # 2. Fast Save Performance Benchmark
    def test_02_fast_save_performance(self):
        """Verify that fast save with DEK executes in < 25ms (ZERO PBKDF2 iterations)."""
        raw_db = b"SQLite format 3\x00" + b"X" * (100 * 1024) # 100 KB
        container, dek, salt, kek_nonce, enc_dek = create_envelope(raw_db, "MasterKey123!")

        # Measure fast save time
        t0 = time.perf_counter()
        fast_cont = fast_save_envelope(raw_db + b"NEW_DATA", dek, salt, kek_nonce, enc_dek)
        elapsed_ms = (time.perf_counter() - t0) * 1000

        self.assertLess(elapsed_ms, 25.0, f"Fast save took {elapsed_ms:.2f}ms, must be < 25ms!")

        # Verify new container decrypts properly
        dec_bytes, _, _, _, _ = open_envelope(fast_cont, "MasterKey123!")
        self.assertEqual(dec_bytes, raw_db + b"NEW_DATA")

    # 3. Storage Persistence & Shadow Backup
    def test_03_atomic_write_and_shadow_backup(self):
        """Verify that saving creates shadow backup (.enc.bak) and replaces .enc atomically."""
        conn = self.storage.initialize_new("SecretPass2026!")
        self.assertTrue(self.enc_path.exists())
        size1 = self.enc_path.stat().st_size

        # Modify database and save
        conn.execute("INSERT INTO system_meta (key, value) VALUES ('meta_key', 'meta_value');")
        conn.commit()
        self.storage.save()

        bak_path = self.enc_path.with_name(f"{self.enc_path.name}.bak")
        self.assertTrue(bak_path.exists(), "Shadow backup (.enc.bak) must be created on update")
        self.assertEqual(bak_path.stat().st_size, size1)

        # Reopen from disk in fresh storage instance
        self.storage.lock()
        fresh_storage = EncryptedDatabaseStorage(self.enc_path)
        fresh_conn = fresh_storage.open("SecretPass2026!")
        cur = fresh_conn.cursor()
        cur.execute("SELECT value FROM system_meta WHERE key='meta_key';")
        self.assertEqual(cur.fetchone()[0], "meta_value")
        fresh_storage.lock()

    # 4. Memory Key Wiping on Lock
    def test_04_key_wiping_on_lock(self):
        """Verify that locking zeros out the DEK bytearray in memory."""
        self.storage.initialize_new("Pass123456!")
        dek_ref = self.storage._dek
        self.assertIsNotNone(dek_ref)
        self.assertTrue(any(b != 0 for b in dek_ref))

        self.storage.lock()
        self.assertIsNone(self.storage._dek)
        self.assertTrue(all(b == 0 for b in dek_ref), "DEK bytes in RAM must be zeroed out on lock!")

    # 5. Wrong Password & Cryptographic Tampering
    def test_05_tampering_and_wrong_password_rejection(self):
        """Verify that wrong password and bit flipping in container are rejected with PermissionError."""
        self.storage.initialize_new("CorrectPassword123!")
        self.storage.lock()

        # 1. Wrong password
        with self.assertRaises(PermissionError):
            self.storage.open("WrongPassword999!")

        # 2. Tampered ciphertext (flip a byte in the container)
        container_bytes = bytearray(self.enc_path.read_bytes())
        container_bytes[-5] ^= 0xFF # Flip bit in GCM tag/ciphertext
        self.enc_path.write_bytes(bytes(container_bytes))

        with self.assertRaises(PermissionError):
            self.storage.open("CorrectPassword123!")

    # 6. Master Password Rotation
    def test_06_master_password_rotation(self):
        """Verify password change re-encrypts DEK with new KEK and preserves database contents."""
        conn = self.storage.initialize_new("OldPassword123!")
        conn.execute("INSERT INTO system_meta (key, value) VALUES ('rotate_test', 'persisted');")
        conn.commit()
        self.storage.save()

        # Change password
        ok = self.storage.change_password("OldPassword123!", "NewStrongPassword456!")
        self.assertTrue(ok)
        self.storage.lock()

        # Old password must now fail
        with self.assertRaises(PermissionError):
            self.storage.open("OldPassword123!")

        # New password must succeed and have preserved data
        restored = self.storage.open("NewStrongPassword456!")
        cur = restored.cursor()
        cur.execute("SELECT value FROM system_meta WHERE key='rotate_test';")
        self.assertEqual(cur.fetchone()[0], "persisted")
        self.storage.lock()

    # 7. DNS Rebinding Protection
    def test_07_dns_rebinding_protection(self):
        """Verify that requests with unauthorized external Host headers are rejected (403)."""
        handler = FamilyFinancesHandler
        # 1. Allowed hosts: 127.0.0.1, localhost, LAN IPs
        for valid_host in ["127.0.0.1", "127.0.0.1:8000", "localhost", "192.168.1.50:8000"]:
            req = f"GET /api/status HTTP/1.1\r\nHost: {valid_host}\r\n\r\n".encode()
            sock = MockSocket(req)
            handler(sock, ("127.0.0.1", 12345), None)
            self.assertIn(b"200 OK", bytes(sock.output), f"Host {valid_host} must be accepted")

        # 2. Forbidden hosts: external/attacker domains
        for evil_host in ["attacker.com", "malicious-site.org", "rebind.network"]:
            req = f"GET /api/status HTTP/1.1\r\nHost: {evil_host}\r\n\r\n".encode()
            sock = MockSocket(req)
            handler(sock, ("127.0.0.1", 12345), None)
            self.assertIn(b"403", bytes(sock.output), f"Host {evil_host} must be rejected with 403")

    # 8. Security Headers
    def test_08_security_headers(self):
        """Verify X-Content-Type-Options, X-Frame-Options, CSP, and Referrer-Policy headers."""
        req = b"GET /api/status HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
        sock = MockSocket(req)
        FamilyFinancesHandler(sock, ("127.0.0.1", 12345), None)
        out = bytes(sock.output)

        self.assertIn(b"X-Content-Type-Options: nosniff", out)
        self.assertIn(b"X-Frame-Options: DENY", out)
        self.assertIn(b"Content-Security-Policy: default-src 'self' 'unsafe-inline' data:;", out)
        self.assertIn(b"Referrer-Policy: no-referrer", out)

    # 9. Web Server Unlock and Lock Endpoints
    def test_09_web_server_unlock_and_lock(self):
        """Verify /api/unlock and /api/lock API lifecycle."""
        # Initialize an encrypted DB on disk
        self.storage.initialize_new("WebSecret2026!")
        self.storage.lock()

        # Point handler storage to test storage
        original_storage = FamilyFinancesHandler.storage
        FamilyFinancesHandler.storage = self.storage
        try:
            # 1. Status shows locked
            req_status = b"GET /api/status HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
            sock_st = MockSocket(req_status)
            FamilyFinancesHandler(sock_st, ("127.0.0.1", 12345), None)
            self.assertIn(b'"is_locked": true', bytes(sock_st.output))

            # 2. Request to /api/overview returns 423 Locked
            req_ov = b"GET /api/overview HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
            sock_ov = MockSocket(req_ov)
            FamilyFinancesHandler(sock_ov, ("127.0.0.1", 12345), None)
            self.assertIn(b"423", bytes(sock_ov.output))

            # 3. Unlock with wrong password returns 401
            req_bad_unl = b"POST /api/unlock HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 29\r\n\r\n{\"password\": \"WrongPass!\"}"
            sock_bad = MockSocket(req_bad_unl)
            FamilyFinancesHandler(sock_bad, ("127.0.0.1", 12345), None)
            self.assertIn(b"401", bytes(sock_bad.output))

            # 4. Unlock with correct password returns 200 and unlocks
            req_good_unl = b"POST /api/unlock HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 32\r\n\r\n{\"password\": \"WebSecret2026!\"}"
            sock_good = MockSocket(req_good_unl)
            FamilyFinancesHandler(sock_good, ("127.0.0.1", 12345), None)
            self.assertIn(b"200 OK", bytes(sock_good.output))
            self.assertTrue(self.storage.is_unlocked())

            # 5. Lock endpoint locks and clears RAM
            req_lock = b"POST /api/lock HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 2\r\n\r\n{}"
            sock_lock = MockSocket(req_lock)
            FamilyFinancesHandler(sock_lock, ("127.0.0.1", 12345), None)
            self.assertIn(b"200 OK", bytes(sock_lock.output))
            self.assertFalse(self.storage.is_unlocked())
        finally:
            FamilyFinancesHandler.storage = original_storage

    # 10. CLI Migration Execution
    def test_10_migration_command_execution(self):
        """Verify CLI migrate-to-encrypted command converts plaintext WAL DB to encrypted container."""
        from family_finances_os.cli import cmd_migrate_to_encrypted
        import argparse

        # Create a mock source DB in test_dir
        mock_plain_db = Path(self.test_dir) / "source_mock.db"
        init_database(mock_plain_db)
        conn = sqlite3.connect(str(mock_plain_db))
        conn.execute("INSERT INTO system_meta (key, value) VALUES ('mig_test', 'persisted_val');")
        conn.commit()
        conn.close()

        # Temporarily mock DB_PATH and ENC_DB_PATH
        import family_finances_os.cli as cli_mod
        orig_db_path = cli_mod.DB_PATH
        orig_enc_path = cli_mod.ENC_DB_PATH

        target_enc = Path(self.test_dir) / "source_mock.db.enc"
        cli_mod.DB_PATH = mock_plain_db
        cli_mod.ENC_DB_PATH = target_enc
        try:
            mock_args = argparse.Namespace(password="MigratedKey2026!")
            cmd_migrate_to_encrypted(mock_args)

            # Plaintext original must be deleted
            self.assertFalse(mock_plain_db.exists(), "Original plaintext DB must be unlinked after migration")
            # Plaintext backup must exist
            backup_db = mock_plain_db.with_suffix(".db.plaintext_backup")
            self.assertTrue(backup_db.exists(), "Plaintext backup must exist")
            # Encrypted container must exist
            self.assertTrue(target_enc.exists(), "Encrypted container must exist")

            # Verify container contents
            test_storage = EncryptedDatabaseStorage(target_enc)
            conn = test_storage.open("MigratedKey2026!")
            cur = conn.cursor()
            cur.execute("SELECT value FROM system_meta WHERE key='mig_test';")
            self.assertEqual(cur.fetchone()[0], "persisted_val")
            test_storage.lock()
        finally:
            cli_mod.DB_PATH = orig_db_path
            cli_mod.ENC_DB_PATH = orig_enc_path


if __name__ == "__main__":
    unittest.main(verbosity=2)
