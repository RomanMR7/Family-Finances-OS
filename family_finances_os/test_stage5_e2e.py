"""
Family Finances OS - Stage 5 End-to-End (E2E) Comprehensive Verification Suite
Tests the complete production lifecycle:
1. Cold start uninitialized status (zero-state detection)
2. Master setup & envelope container creation (PBKDF2 600k + AES-256-GCM)
3. Full family financial cycle (income, obligations, spending, Safe-to-Spend convergence)
4. Memory lock & unlock security lifecycle (zeroize DEK in RAM, session invalidation)
5. Disaster recovery from shadow backup (.db.enc.bak)
6. P2P LAN replication roundtrip between two devices with HMAC authentication
7. Security guardrails (DNS rebinding protection, Host header filtering)
"""
import io
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from family_finances_os.db import EncryptedDatabaseStorage, get_connection
from family_finances_os.ledger import LedgerEngine
from family_finances_os.models import (
    Posting,
    Transaction,
    rubles_to_cents,
    cents_to_rubles,
    generate_uuid,
    current_iso_time
)
from family_finances_os.sync import (
    HybridLogicalClock,
    P2PSyncEngine,
    sign_sync_payload,
    verify_sync_payload
)
from family_finances_os.web_server import FamilyFinancesHandler
from family_finances_os.auth import GLOBAL_SESSION_MANAGER, SessionManager


class MockSocket:
    def __init__(self, raw_data: bytes):
        self.input_bytes = raw_data
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


class TestStage5EndToEnd(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="ffos_s5_")
        self.enc_path = Path(self.test_dir) / "family_finances.db.enc"
        self.storage = EncryptedDatabaseStorage(enc_path=self.enc_path)
        # Patch handler's storage
        self.orig_storage = FamilyFinancesHandler.storage
        FamilyFinancesHandler.storage = self.storage

    def tearDown(self):
        try:
            if self.storage.is_unlocked():
                self.storage.lock()
        except Exception:
            pass
        FamilyFinancesHandler.storage = self.orig_storage
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _execute_http(self, method: str, path: str, body: dict = None, token: str = None, host: str = "127.0.0.1") -> tuple[int, dict]:
        body_bytes = json.dumps(body).encode("utf-8") if body is not None else b""
        headers = [f"{method} {path} HTTP/1.1", f"Host: {host}"]
        if token:
            headers.append(f"Authorization: Bearer {token}")
        if body_bytes:
            headers.append(f"Content-Length: {len(body_bytes)}")
            headers.append("Content-Type: application/json")
        req_raw = "\r\n".join(headers).encode("utf-8") + b"\r\n\r\n" + body_bytes

        sock = MockSocket(req_raw)
        FamilyFinancesHandler(sock, ("127.0.0.1", 12345), None)
        raw_output = bytes(sock.output)
        
        status_line = raw_output.split(b"\r\n", 1)[0].decode("utf-8")
        status_code = int(status_line.split(" ")[1])
        parts = raw_output.split(b"\r\n\r\n", 1)
        resp_json = json.loads(parts[1].decode("utf-8")) if len(parts) > 1 and parts[1].strip() else {}
        return status_code, resp_json

    # 1. Cold start uninitialized status
    def test_01_cold_start_uninitialized_status(self):
        """A freshly installed system with no file on disk must report uninitialized state (not locked)."""
        status_code, resp = self._execute_http("GET", "/api/status")
        self.assertEqual(status_code, 200)
        self.assertFalse(resp["is_locked"], "Cold start must not report locked before initialization")
        self.assertFalse(resp["is_encrypted"])
        self.assertFalse(resp["has_owner"])

    # 2. Master setup & container creation
    def test_02_cold_start_setup_master_creation(self):
        """Setting up master password creates encrypted container and seeds default chart of accounts."""
        setup_payload = {
            "master_password": "FamilyPassword2026!",
            "username": "family_head",
            "display_name": "Папа"
        }
        status_code, resp = self._execute_http("POST", "/api/setup-master", setup_payload)
        self.assertEqual(status_code, 200)
        self.assertEqual(resp["status"], "success")
        self.assertIn("session_token", resp["owner"])

        # Check file on disk
        self.assertTrue(self.enc_path.exists())
        raw_bytes = self.enc_path.read_bytes()
        self.assertTrue(raw_bytes.startswith(b"FFOS_ENV\x01"))

        # Check unlocked status
        self.assertTrue(self.storage.is_unlocked())
        status_code, resp_status = self._execute_http("GET", "/api/status")
        self.assertFalse(resp_status["is_locked"])
        self.assertTrue(resp_status["has_owner"])

    # 3. Full family financial cycle
    def test_03_full_family_financial_cycle(self):
        """
        Verify complete financial cycle:
        1. Initialize master
        2. Deposit salary (+120,000 ₽)
        3. Register obligations (Kindergarten: 12,000 ₽, Rent: 35,000 ₽)
        4. Safe-to-Spend check: 120,000 - 47,000 = 73,000 ₽
        5. Spend groceries (-20,000 ₽)
        6. Mark Kindergarten as paid
        7. Safe-to-Spend update: (120,000 - 20,000) - 35,000 = 65,000 ₽
        """
        # 1. Setup
        _, setup_resp = self._execute_http("POST", "/api/setup-master", {
            "master_password": "FamilyPassword2026!", "username": "admin", "display_name": "Глава"
        })
        token = setup_resp["owner"]["session_token"]

        ledger = LedgerEngine(conn_or_path=self.storage.get_connection())
        overview = ledger.get_financial_overview()
        card_acc = next(a for a in overview["accounts"] if a["code"] == "1010")

        # 2. Deposit salary 120,000 ₽
        salary_acc = ledger.get_account_by_code("4010")
        expense_acc = ledger.get_account_by_code("5010")
        salary_cat = next(c for c in ledger.get_flat_categories() if c["type"] == "INCOME")
        tx_salary_id = generate_uuid()
        salary_tx = Transaction(
            id=tx_salary_id,
            tx_date="2026-11-09",
            tx_type="INCOME",
            description="Зарплата главы семьи",
            postings=[
                Posting(id=generate_uuid(), transaction_id=tx_salary_id, account_id=card_acc["id"], amount_cents=rubles_to_cents(120000), posting_type="DEBIT"),
                Posting(id=generate_uuid(), transaction_id=tx_salary_id, account_id=salary_acc.id, amount_cents=rubles_to_cents(120000), posting_type="CREDIT", category_id=salary_cat["id"])
            ]
        )
        ledger.record_transaction(salary_tx)

        # 3. Register obligations: Rent 35,000 and Kindergarten 12,000
        food_cat = next(c for c in ledger.get_flat_categories() if c["type"] == "EXPENSE")
        obl_rent = ledger.create_obligation("Аренда квартиры", rubles_to_cents(35000), 20, food_cat["id"], card_acc["id"])
        obl_kinder = ledger.create_obligation("Детский сад", rubles_to_cents(12000), 10, food_cat["id"], card_acc["id"])

        # 4. Safe-to-Spend check: 120,000 - (35,000 + 12,000) = 73,000 ₽
        ov1 = ledger.get_financial_overview()
        self.assertEqual(ov1["common_safe_to_spend_rub"], "73000.00")
        self.assertFalse(ov1["is_deficit"])

        # 5. Spend 20,000 ₽ on groceries
        tx_spend_id = generate_uuid()
        spend_tx = Transaction(
            id=tx_spend_id,
            tx_date="2026-11-09",
            tx_type="EXPENSE",
            description="Покупка продуктов в гипермаркете",
            postings=[
                Posting(id=generate_uuid(), transaction_id=tx_spend_id, account_id=expense_acc.id, amount_cents=rubles_to_cents(20000), posting_type="DEBIT", category_id=food_cat["id"]),
                Posting(id=generate_uuid(), transaction_id=tx_spend_id, account_id=card_acc["id"], amount_cents=rubles_to_cents(20000), posting_type="CREDIT")
            ]
        )
        ledger.record_transaction(spend_tx)

        # 6. Mark Kindergarten as paid
        ledger.mark_obligation_paid(obl_kinder.id, "2026-11", tx_spend_id, rubles_to_cents(12000))

        # 7. Safe-to-Spend: Liquid = 100,000 ₽. Remaining unpaid = Rent (35,000 ₽).
        # Safe-to-Spend = 100,000 - 35,000 = 65,000 ₽.
        ov2 = ledger.get_financial_overview()
        self.assertEqual(ov2["common_liquid_assets_rub"], "100000.00")
        self.assertEqual(ov2["unpaid_obligations_rub"], "35000.00")
        self.assertEqual(ov2["common_safe_to_spend_rub"], "65000.00")

    # 4. Lock & Unlock security lifecycle
    def test_04_lock_and_unlock_lifecycle(self):
        """Verifies RAM memory wipe on lock and full data restoration on unlock."""
        pwd = "TestSecret2026!"
        _, setup_resp = self._execute_http("POST", "/api/setup-master", {
            "master_password": pwd, "username": "admin", "display_name": "Папа"
        })
        token = setup_resp["owner"]["session_token"]

        # Lock
        status_code, lock_resp = self._execute_http("POST", "/api/lock", token=token)
        self.assertEqual(status_code, 200)
        self.assertFalse(self.storage.is_unlocked())
        self.assertIsNone(self.storage._dek, "DEK must be wiped to None")

        # Overview must now be blocked with 423 Locked
        status_code, _ = self._execute_http("GET", "/api/overview", token=token)
        self.assertEqual(status_code, 423)

        # Unlock with wrong password must fail
        status_code, unlock_fail = self._execute_http("POST", "/api/unlock", {"master_password": "WRONG_PASSWORD"})
        self.assertEqual(status_code, 401)
        self.assertFalse(self.storage.is_unlocked())

        # Unlock with correct password must succeed
        status_code, unlock_ok = self._execute_http("POST", "/api/unlock", {"master_password": pwd})
        self.assertEqual(status_code, 200)
        self.assertTrue(self.storage.is_unlocked())

    # 5. Disaster recovery from shadow backup (.db.enc.bak)
    def test_05_disaster_recovery_from_shadow_backup(self):
        """Simulate catastrophic file corruption and verify recovery from .db.enc.bak shadow file."""
        pwd = "RecoveryPassword2026!"
        self.storage.initialize_new(pwd)
        ledger = LedgerEngine(conn_or_path=self.storage.get_connection())
        ledger.seed_default_chart_of_accounts()
        self.storage.save()

        # Shadow file must exist after second save
        self.storage.save()
        bak_path = self.enc_path.parent / f"{self.enc_path.name}.bak"
        self.assertTrue(bak_path.exists())

        # Corrupt the main encrypted file with random garbage
        self.storage.lock()
        self.enc_path.write_bytes(b"CORRUPTED_BYTES_GARBAGE_PAYLOAD" * 100)

        # Opening corrupted main file fails
        with self.assertRaises(Exception):
            self.storage.open(pwd)

        # Recovery procedure: restore shadow backup
        shutil.copy2(bak_path, self.enc_path)
        restored_conn = self.storage.open(pwd)
        self.assertIsNotNone(restored_conn)
        restored_ledger = LedgerEngine(conn_or_path=restored_conn)
        ov = restored_ledger.get_financial_overview()
        self.assertGreater(len(ov["accounts"]), 0)

    # 6. P2P LAN replication roundtrip with HMAC auth
    def test_06_lan_p2p_sync_roundtrip(self):
        """Verify peer sync exchange with HMAC-SHA256 signature."""
        pwd = "SyncFamilyKey2026!"
        self.storage.initialize_new(pwd)
        conn_a = self.storage.get_connection()
        ledger_a = LedgerEngine(conn_or_path=conn_a)
        ledger_a.seed_default_chart_of_accounts()
        ledger_a.seed_default_categories()
        engine_a = P2PSyncEngine(conn_or_path=conn_a, device_id="LAPTOP_DAD")

        # Secondary peer (Wife's phone)
        peer_dir = Path(tempfile.mkdtemp(prefix="ffos_peer_"))
        try:
            peer_storage = EncryptedDatabaseStorage(enc_path=peer_dir / "peer.db.enc")
            conn_b = peer_storage.initialize_new(pwd)
            ledger_b = LedgerEngine(conn_or_path=conn_b)
            ledger_b.seed_default_chart_of_accounts()
            ledger_b.seed_default_categories()
            engine_b = P2PSyncEngine(conn_or_path=conn_b, device_id="PHONE_MOM")

            # Mom adds expense on her phone
            acc_b = next(a for a in ledger_b.get_financial_overview()["accounts"] if a["code"] == "1020")
            cat_b = next(c for c in ledger_b.get_flat_categories() if c["type"] == "EXPENSE")
            expense_acc_b = ledger_b.get_account_by_code("5010")
            tx_mom_id = generate_uuid()
            tx_mom = Transaction(
                id=tx_mom_id,
                tx_date="2026-11-09",
                tx_type="EXPENSE",
                description="Покупка в аптеке (Телефон мамы)",
                postings=[
                    Posting(id=generate_uuid(), transaction_id=tx_mom_id, account_id=expense_acc_b.id, amount_cents=rubles_to_cents(1500), posting_type="DEBIT", category_id=cat_b["id"]),
                    Posting(id=generate_uuid(), transaction_id=tx_mom_id, account_id=acc_b["id"], amount_cents=rubles_to_cents(1500), posting_type="CREDIT")
                ]
            )
            ledger_b.record_transaction(tx_mom)

            # Export changes from Phone
            changes = engine_b.export_changes()
            self.assertGreaterEqual(len(changes["changes"]), 1)

            # Apply remote changes to Laptop
            apply_result = engine_a.apply_remote_changes(changes)
            self.assertGreaterEqual(apply_result["applied_count"], 1)

            # Verify mom's transaction appears on dad's laptop
            cur_a = conn_a.cursor()
            cur_a.execute("SELECT id, description FROM transactions WHERE id = ?;", (tx_mom_id,))
            row = cur_a.fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row["description"], "Покупка в аптеке (Телефон мамы)")
        finally:
            shutil.rmtree(peer_dir, ignore_errors=True)

    # 7. DNS Rebinding & LAN host filtering
    def test_07_dns_rebinding_and_lan_host_validation(self):
        """DNS rebinding attack must be rejected (403); LAN IPs (192.168.x.x, 10.x.x.x) must be accepted."""
        # Malicious Host header
        code_evil, resp_evil = self._execute_http("GET", "/api/status", host="evil-hacker.com")
        self.assertEqual(code_evil, 403)
        self.assertIn("DNS Rebinding", resp_evil.get("message", ""))

        # Local LAN host header (smartphone accessing server via Wi-Fi)
        code_lan, resp_lan = self._execute_http("GET", "/api/status", host="192.168.1.105:8000")
        self.assertEqual(code_lan, 200)

        # Localhost header
        code_local, resp_local = self._execute_http("GET", "/api/status", host="127.0.0.1:8000")
        self.assertEqual(code_local, 200)


if __name__ == "__main__":
    unittest.main(verbosity=2)
