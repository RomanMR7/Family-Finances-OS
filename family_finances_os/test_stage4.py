"""
Family Finances OS - Stage 4 Comprehensive Verification Test Suite
Tests all requirements of Stage 4 (Offline-First Local P2P Synchronization):
1. Hybrid Logical Clock (HLC) monotonicity and remote drift forward-catch
2. Comprehensive Change Data Capture (CDC) event logging across all domain mutations
3. Bidirectional offline sync between two independent devices (Alice & Bob)
4. Commutative double-entry ledger convergence and exact Safe-to-Spend equality
5. Idempotent deduplication (re-syncing does not duplicate transactions or corrupt balances)
6. Deterministic Last-Write-Wins (LWW) conflict resolution for master entities
7. Tombstone replication for voided transactions
8. HMAC-SHA256 mutual pairing authentication & tampering rejection
9. Web API sync endpoints (GET /api/sync/status, POST /api/sync/pull, POST /api/sync/push)
"""
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from family_finances_os.db import init_database, get_connection
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
from family_finances_os.web_server import FamilyFinancesHandler, GLOBAL_SESSION_MANAGER


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


class TestStage4P2PSynchronization(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="ffos_s4_")
        self.db_path_a = Path(self.test_dir) / "node_a.db"
        self.db_path_b = Path(self.test_dir) / "node_b.db"

        init_database(self.db_path_a)
        init_database(self.db_path_b)

        self.engine_a = P2PSyncEngine(conn_or_path=self.db_path_a, device_id="DEVICE_ALICE")
        self.engine_b = P2PSyncEngine(conn_or_path=self.db_path_b, device_id="DEVICE_BOB")

        self.ledger_a = LedgerEngine(conn_or_path=self.db_path_a)
        self.ledger_b = LedgerEngine(conn_or_path=self.db_path_b)

        self.ledger_a.seed_default_chart_of_accounts()
        self.ledger_b.seed_default_chart_of_accounts()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    # 1. Hybrid Logical Clock Monotonicity
    def test_01_hybrid_logical_clock_monotonicity(self):
        """Test HLC monotonic increment and drift catching."""
        hlc = HybridLogicalClock("DEV_1")
        t1 = hlc.now()
        t2 = hlc.now()
        t3 = hlc.now()

        self.assertLess(t1, t2)
        self.assertLess(t2, t3)

        # Simulate receiving timestamp from peer with higher physical time
        future_ts = "99999999999999:00005:DEV_2"
        hlc.update(future_ts)
        t_after = hlc.now()
        self.assertGreater(t_after, future_ts)
        self.assertTrue(t_after.startswith("99999999999999"))

    # 2. Comprehensive CDC Event Logging
    def test_02_cdc_event_logging_on_mutations(self):
        """Verify that every domain mutation records a complete CDC event in change_log."""
        # 1. Create account
        acc = self.ledger_a.create_account("Наличный сейф", "ASSET", "CASH", "COMMON")
        # 2. Create category
        cat = self.ledger_a.create_category("Коммуналка", "EXPENSE", icon="⚡")
        # 3. Create obligation
        obl = self.ledger_a.create_obligation("Взнос за капремонт", rubles_to_cents(1500), 10)
        # 4. Mark obligation paid
        self.ledger_a.mark_obligation_paid(obl.id, "2026-11")

        # 5. Record transaction
        tx_id = generate_uuid()
        salary = self.ledger_a.get_account_by_code("4010")
        card = self.ledger_a.get_account_by_code("1010")
        tx = Transaction(
            id=tx_id, tx_date="2026-11-09", tx_type="INCOME", description="Зарплата ноябрь", created_by_member_id=None,
            postings=[
                Posting(id=generate_uuid(), transaction_id=tx_id, account_id=card.id, amount_cents=10000000, posting_type="DEBIT"),
                Posting(id=generate_uuid(), transaction_id=tx_id, account_id=salary.id, amount_cents=10000000, posting_type="CREDIT")
            ]
        )
        self.ledger_a.record_transaction(tx)

        # 6. Void transaction
        self.ledger_a.void_transaction(tx_id, "Ошибочное начисление")

        # Check change_log table
        conn = get_connection(self.db_path_a)
        cursor = conn.cursor()
        cursor.execute("SELECT entity_name, change_type, hlc_timestamp FROM change_log ORDER BY local_seq ASC;")
        logs = cursor.fetchall()
        conn.close()

        logged_entities = [r["entity_name"] for r in logs]
        logged_types = [r["change_type"] for r in logs]

        self.assertIn("ACCOUNT", logged_entities)
        self.assertIn("CATEGORY", logged_entities)
        self.assertIn("OBLIGATION", logged_entities)
        self.assertIn("OBLIGATION_PAYMENT", logged_entities)
        self.assertIn("TRANSACTION", logged_entities)
        self.assertIn("VOID", logged_types)

    # 3. Bidirectional Offline Sync Between Two Nodes
    def test_03_p2p_bidirectional_sync_two_nodes(self):
        """
        Verify bidirectional synchronization between Alice (Node A) and Bob (Node B):
        - Alice works offline: creates salary transaction + obligation (Детский сад 12,000 ₽)
        - Bob works offline: creates custom account (Кошелек) + groceries expense (3,000 ₽)
        - P2P sync exchange happens over local network.
        - Result: Both nodes have identical transactions, obligations, and Safe-to-Spend!
        """
        # Node A: Alice
        card_a = self.ledger_a.get_account_by_code("1010")
        salary_a = self.ledger_a.get_account_by_code("4010")
        tx_a_id = generate_uuid()
        self.ledger_a.record_transaction(Transaction(
            id=tx_a_id, tx_date="2026-11-09", tx_type="INCOME", description="Алиса Зарплата 80000", created_by_member_id=None,
            postings=[
                Posting(id=generate_uuid(), transaction_id=tx_a_id, account_id=card_a.id, amount_cents=8000000, posting_type="DEBIT"),
                Posting(id=generate_uuid(), transaction_id=tx_a_id, account_id=salary_a.id, amount_cents=8000000, posting_type="CREDIT")
            ]
        ))
        obl_kinder = self.ledger_a.create_obligation("Детский сад", rubles_to_cents(12000), 15)

        # Node B: Bob
        wallet_b = self.ledger_b.create_account("Кошелек Боб", "ASSET", "CASH", "PERSONAL_HUSBAND")
        food_b = self.ledger_b.get_account_by_code("5010")
        card_b = self.ledger_b.get_account_by_code("1010")
        tx_b_id = generate_uuid()
        self.ledger_b.record_transaction(Transaction(
            id=tx_b_id, tx_date="2026-11-09", tx_type="EXPENSE", description="Боб Продукты 3000", created_by_member_id=None,
            postings=[
                Posting(id=generate_uuid(), transaction_id=tx_b_id, account_id=food_b.id, amount_cents=300000, posting_type="DEBIT"),
                Posting(id=generate_uuid(), transaction_id=tx_b_id, account_id=card_b.id, amount_cents=300000, posting_type="CREDIT")
            ]
        ))

        # --- P2P SYNC EXCHANGE ---
        # 1. Node A exports to Node B
        changes_from_a = self.engine_a.export_changes()
        res_apply_b = self.engine_b.apply_remote_changes(changes_from_a)
        self.assertGreater(res_apply_b["applied_count"], 0)

        # 2. Node B exports to Node A
        changes_from_b = self.engine_b.export_changes()
        res_apply_a = self.engine_a.apply_remote_changes(changes_from_b)
        self.assertGreater(res_apply_a["applied_count"], 0)

        # --- VERIFICATION OF MATHEMATICAL CONVERGENCE ---
        overview_a = self.ledger_a.get_financial_overview()
        overview_b = self.ledger_b.get_financial_overview()

        # Both must have 80,000 - 3,000 = 77,000 RUB liquid
        self.assertEqual(overview_a["common_liquid_assets_cents"], 7700000)
        self.assertEqual(overview_b["common_liquid_assets_cents"], 7700000)

        # Both must have 12,000 RUB unpaid obligation
        self.assertEqual(overview_a["unpaid_obligations_cents"], 1200000)
        self.assertEqual(overview_b["unpaid_obligations_cents"], 1200000)

        # Both must have Safe-to-Spend = 77,000 - 12,000 = 65,000 RUB!
        self.assertEqual(overview_a["common_safe_to_spend_cents"], 6500000)
        self.assertEqual(overview_b["common_safe_to_spend_cents"], 6500000)

        # Both must have "Кошелек Боб"
        self.assertIsNotNone(self.ledger_a.get_account_by_id(wallet_b.id))
        self.assertIsNotNone(self.ledger_b.get_account_by_id(wallet_b.id))

    # 4. Idempotent Deduplication
    def test_04_idempotent_deduplication(self):
        """Applying the exact same change batch twice must be idempotent."""
        card_a = self.ledger_a.get_account_by_code("1010")
        salary_a = self.ledger_a.get_account_by_code("4010")
        tx_id = generate_uuid()
        self.ledger_a.record_transaction(Transaction(
            id=tx_id, tx_date="2026-11-09", tx_type="INCOME", description="Премия", created_by_member_id=None,
            postings=[
                Posting(id=generate_uuid(), transaction_id=tx_id, account_id=card_a.id, amount_cents=5000000, posting_type="DEBIT"),
                Posting(id=generate_uuid(), transaction_id=tx_id, account_id=salary_a.id, amount_cents=5000000, posting_type="CREDIT")
            ]
        ))

        # First sync
        batch = self.engine_a.export_changes()
        res1 = self.engine_b.apply_remote_changes(batch)
        self.assertEqual(res1["applied_count"], 1)
        self.assertEqual(res1["skipped_count"], 0)

        # Re-apply identical batch
        res2 = self.engine_b.apply_remote_changes(batch)
        self.assertEqual(res2["applied_count"], 0)
        self.assertEqual(res2["skipped_count"], 1)

        # Balance on Node B must NOT be doubled
        bal = self.ledger_b.get_account_balance_cents(card_a.id)
        self.assertEqual(bal, 5000000)

    # 5. Deterministic LWW Conflict Resolution
    def test_05_deterministic_lww_conflict_resolution(self):
        """Master entities use Last-Write-Wins based on HLC timestamps."""
        acc_a = self.ledger_a.create_account("Вклад Т-Банк 15%", "ASSET", "DEPOSIT", "COMMON")
        # Sync account to Node B
        self.engine_b.apply_remote_changes(self.engine_a.export_changes())

        # Update on Node A at time 1
        self.ledger_a.update_account(acc_a.id, name="Вклад Т-Банк 16% (Старая ставка)")

        # Update on Node B at time 2 (with higher HLC)
        self.ledger_b.update_account(acc_a.id, name="Вклад Т-Банк 18% (Победная ставка)")

        # Sync B -> A
        self.engine_a.apply_remote_changes(self.engine_b.export_changes())

        updated_a = self.ledger_a.get_account_by_id(acc_a.id)
        self.assertEqual(updated_a.name, "Вклад Т-Банк 18% (Победная ставка)")

    # 6. Tombstone Replication for Voided Transactions
    def test_06_voided_transaction_replication(self):
        """Voided transactions replicate is_voided=1 and rebalance accounts on peers."""
        card_a = self.ledger_a.get_account_by_code("1010")
        food_a = self.ledger_a.get_account_by_code("5010")
        tx_id = generate_uuid()
        self.ledger_a.record_transaction(Transaction(
            id=tx_id, tx_date="2026-11-09", tx_type="EXPENSE", description="Ошибочная покупка", created_by_member_id=None,
            postings=[
                Posting(id=generate_uuid(), transaction_id=tx_id, account_id=food_a.id, amount_cents=450000, posting_type="DEBIT"),
                Posting(id=generate_uuid(), transaction_id=tx_id, account_id=card_a.id, amount_cents=450000, posting_type="CREDIT")
            ]
        ))
        # Sync creation to Node B
        self.engine_b.apply_remote_changes(self.engine_a.export_changes())
        self.assertEqual(self.ledger_b.get_account_balance_cents(card_a.id), -450000)

        # Void on Node A
        self.ledger_a.void_transaction(tx_id, "Возврат средств продавцом")

        # Sync void to Node B
        self.engine_b.apply_remote_changes(self.engine_a.export_changes())

        # Node B must now have 0 balance (voided transaction does not affect balance)
        self.assertEqual(self.ledger_b.get_account_balance_cents(card_a.id), 0)

    # 7. HMAC-SHA256 Mutual Pairing Security
    def test_07_hmac_sync_security(self):
        """Verify HMAC signature calculation and constant-time tampering rejection."""
        secret = "MY_FAMILY_SECRET_KEY"
        body = b'{"changes": [{"entity": "TRANSACTION"}]}'
        nonce = "1234567890abcdef"
        hlc = "00001731145200:00001:NODE1"

        valid_sig = sign_sync_payload(body, secret, nonce, hlc)
        self.assertTrue(verify_sync_payload(body, secret, nonce, hlc, valid_sig))

        # Tampered body must fail
        tampered_body = b'{"changes": [{"entity": "FRAUD"}]}'
        self.assertFalse(verify_sync_payload(tampered_body, secret, nonce, hlc, valid_sig))

        # Wrong secret must fail
        self.assertFalse(verify_sync_payload(body, "WRONG_SECRET", nonce, hlc, valid_sig))

    # 8. Web API Sync Endpoints
    def test_08_web_api_sync_endpoints(self):
        """Verify GET /api/sync/status, POST /api/sync/pull, POST /api/sync/push via HTTP handler."""
        user_info = {"user_id": "u_test", "username": "admin", "role": "OWNER"}
        valid_token = GLOBAL_SESSION_MANAGER.create_session(user_info)

        # 1. GET /api/sync/status
        req_status = f"GET /api/sync/status HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {valid_token}\r\n\r\n".encode()
        sock_status = MockSocket(req_status)
        FamilyFinancesHandler(sock_status, ("127.0.0.1", 12345), None)
        self.assertIn(b"200 OK", bytes(sock_status.output))
        resp_status = json.loads(bytes(sock_status.output).split(b"\r\n\r\n", 1)[1])
        self.assertIn("device_id", resp_status)
        self.assertIn("current_hlc", resp_status)

        # 2. POST /api/sync/pull
        pull_payload = json.dumps({"since_hlc": None}).encode()
        req_pull = f"POST /api/sync/pull HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {valid_token}\r\nContent-Length: {len(pull_payload)}\r\n\r\n".encode() + pull_payload
        sock_pull = MockSocket(req_pull)
        FamilyFinancesHandler(sock_pull, ("127.0.0.1", 12345), None)
        self.assertIn(b"200 OK", bytes(sock_pull.output))

        # 3. POST /api/sync/push
        push_payload = json.dumps({
            "sender_device_id": "REMOTE_PHONE",
            "current_hlc": "00001731145200:00001:REMOTE_PHONE",
            "changes": []
        }).encode()
        req_push = f"POST /api/sync/push HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {valid_token}\r\nContent-Length: {len(push_payload)}\r\n\r\n".encode() + push_payload
        sock_push = MockSocket(req_push)
        FamilyFinancesHandler(sock_push, ("127.0.0.1", 12345), None)
        self.assertIn(b"200 OK", bytes(sock_push.output))


if __name__ == "__main__":
    unittest.main(verbosity=2)
