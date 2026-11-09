"""
Family Finances OS - Stage 10 Test Suite
Verification of Savings Envelopes (Конверты-копилки) and Setup Persistence
"""
import io
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from family_finances_os.db import init_database, EncryptedDatabaseStorage, get_connection
from family_finances_os.models import Envelope, EnvelopeOperation, Account
from family_finances_os.ledger import LedgerEngine
from family_finances_os.auth import AuthService
from family_finances_os.sync import P2PSyncEngine
from family_finances_os.web_server import FamilyFinancesHandler, GLOBAL_SESSION_MANAGER


class MockSocket:
    def __init__(self, request_bytes: bytes):
        self.rfile = io.BytesIO(request_bytes)
        self.output = bytearray()

    def makefile(self, mode, *args, **kwargs):
        if "b" in mode:
            if "r" in mode:
                return self.rfile
            elif "w" in mode:
                return MockSocketWriter(self.output)
        raise ValueError(f"Unsupported mock mode: {mode}")

    def sendall(self, data):
        self.output.extend(data)


class MockSocketWriter(io.RawIOBase):
    def __init__(self, buf: bytearray):
        self.buf = buf

    def write(self, b):
        self.buf.extend(b)
        return len(b)


class TestStage10EnvelopesAndPersistence(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="ffos_s10_")
        self.db_path = Path(self.test_dir) / "test_stage10.db"
        self.enc_path = Path(self.test_dir) / "test_stage10.db.enc"

        init_database(self.db_path)
        self.conn = get_connection(self.db_path)
        self.auth = AuthService(conn_or_path=self.conn)
        self.owner_info = self.auth.create_owner("admin", "Глава семьи", "Family2026!")
        auth_res = self.auth.authenticate("admin", "Family2026!")
        self.token = auth_res["session_token"]

        self.ledger = LedgerEngine(conn_or_path=self.conn)
        self.ledger.seed_default_chart_of_accounts()
        self.ledger.seed_default_categories()
        self.sync = P2PSyncEngine(conn_or_path=self.conn)

    def tearDown(self):
        try:
            self.conn.close()
        except Exception:
            pass
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _execute_http(self, method: str, path: str, body: dict = None, token: str = None) -> tuple[int, dict]:
        body_bytes = json.dumps(body).encode("utf-8") if body is not None else b""
        headers = [f"{method} {path} HTTP/1.1", "Host: 127.0.0.1"]
        if token:
            headers.append(f"Authorization: Bearer {token}")
        if body_bytes:
            headers.append(f"Content-Length: {len(body_bytes)}")
            headers.append("Content-Type: application/json")
        req_raw = "\r\n".join(headers).encode("utf-8") + b"\r\n\r\n" + body_bytes

        sock = MockSocket(req_raw)
        orig_storage = FamilyFinancesHandler.storage
        test_storage = EncryptedDatabaseStorage(enc_path=self.enc_path)
        test_storage._active_conn = self.conn
        test_storage._dek = bytearray(b"\x01" * 32)
        FamilyFinancesHandler.storage = test_storage
        try:
            FamilyFinancesHandler(sock, ("127.0.0.1", 12345), None)
        finally:
            FamilyFinancesHandler.storage = orig_storage

        raw_output = bytes(sock.output)
        status_line = raw_output.split(b"\r\n", 1)[0].decode("utf-8")
        status_code = int(status_line.split(" ")[1])
        parts = raw_output.split(b"\r\n\r\n", 1)
        resp_data = json.loads(parts[1].decode("utf-8")) if len(parts) > 1 and parts[1].strip() else {}
        return status_code, resp_data

    # 1. Envelope Ledger CRUD
    def test_01_envelope_lifecycle(self):
        """Verify envelope creation, reading, updating and archiving."""
        env = self.ledger.create_envelope(
            name="Отпуск на море",
            target_amount_cents=150_000_00,
            icon="🏖️",
            color="#06b6d4",
            note="Летняя поездка"
        )
        self.assertIsNotNone(env.id)
        self.assertEqual(env.name, "Отпуск на море")
        self.assertEqual(env.target_amount_cents, 150_000_00)
        self.assertEqual(env.current_amount_cents, 0)
        self.assertEqual(env.icon, "🏖️")
        self.assertTrue(env.is_active)

        # Update
        ok = self.ledger.update_envelope(
            envelope_id=env.id,
            name="Отпуск 2027",
            target_amount_cents=200_000_00,
            icon="✈️",
            color="#3b82f6"
        )
        self.assertTrue(ok)

        # Verify update persisted
        envelopes = self.ledger.get_envelopes(active_only=True)
        self.assertEqual(len(envelopes), 1)
        self.assertEqual(envelopes[0]["name"], "Отпуск 2027")
        self.assertEqual(envelopes[0]["target_amount_cents"], 200_000_00)
        self.assertEqual(envelopes[0]["icon"], "✈️")

        # Archive
        archived = self.ledger.archive_envelope(env.id)
        self.assertTrue(archived)
        active_envelopes = self.ledger.get_envelopes(active_only=True)
        self.assertEqual(len(active_envelopes), 0)
        all_envelopes = self.ledger.get_envelopes(active_only=False)
        self.assertEqual(len(all_envelopes), 1)
        self.assertEqual(all_envelopes[0]["is_active"], 0)

    # 2. Envelope Deposits and Linked Account Balances
    def test_02_envelope_deposit_and_withdrawal(self):
        """Verify deposit, withdrawal and overdraft protection."""
        env = self.ledger.create_envelope(
            name="Подушка безопасности",
            target_amount_cents=100_000_00,
            icon="🛡️"
        )

        # Deposit 20,000 RUB into envelope
        res1 = self.ledger.deposit_to_envelope(
            envelope_id=env.id,
            amount_cents=20_000_00,
            member_id=self.owner_info["member_id"],
            note="Пополнение подушки"
        )
        self.assertEqual(res1["status"], "success")

        # Check envelope balance
        envelopes = self.ledger.get_envelopes()
        self.assertEqual(envelopes[0]["current_amount_cents"], 20_000_00)

        # Withdraw 5,000 RUB
        res2 = self.ledger.withdraw_from_envelope(
            envelope_id=env.id,
            amount_cents=5_000_00,
            member_id=self.owner_info["member_id"],
            note="Частичное снятие"
        )
        self.assertEqual(res2["status"], "success")

        envelopes = self.ledger.get_envelopes()
        self.assertEqual(envelopes[0]["current_amount_cents"], 15_000_00)

        # Overdraft protection: trying to withdraw more than envelope has must fail
        with self.assertRaises(ValueError):
            self.ledger.withdraw_from_envelope(
                envelope_id=env.id,
                amount_cents=20_000_00
            )

    # 3. Transfer Between Envelopes
    def test_03_envelope_transfer(self):
        """Verify moving funds between two envelopes."""
        env1 = self.ledger.create_envelope(name="Копилка 1", target_amount_cents=10_000_00)
        env2 = self.ledger.create_envelope(name="Копилка 2", target_amount_cents=10_000_00)

        # Deposit 8,000 to env1
        self.ledger.deposit_to_envelope(envelope_id=env1.id, amount_cents=8_000_00)

        # Transfer 3,000 from env1 to env2
        res = self.ledger.transfer_between_envelopes(
            from_envelope_id=env1.id,
            to_envelope_id=env2.id,
            amount_cents=3_000_00,
            note="Перевод на другую цель"
        )
        self.assertEqual(res["status"], "success")

        # Check balances
        envelopes_map = {e["id"]: e for e in self.ledger.get_envelopes()}
        self.assertEqual(envelopes_map[env1.id]["current_amount_cents"], 5_000_00)
        self.assertEqual(envelopes_map[env2.id]["current_amount_cents"], 3_000_00)

        # Summary
        summary = self.ledger.get_envelopes_summary()
        self.assertEqual(summary["total_saved_cents"], 8_000_00)
        self.assertEqual(summary["total_target_cents"], 20_000_00)
        self.assertEqual(summary["count"], 2)

        # Overdraft: transfer more than available
        with self.assertRaises(ValueError):
            self.ledger.transfer_between_envelopes(
                from_envelope_id=env1.id,
                to_envelope_id=env2.id,
                amount_cents=6_000_00
            )

    # 4. P2P Sync for Envelopes
    def test_04_sync_envelopes_p2p(self):
        """Verify that envelopes and operations are exported and merged via P2P sync."""
        env = self.ledger.create_envelope(name="Ремонт кухни", target_amount_cents=50_000_00)
        self.ledger.deposit_to_envelope(envelope_id=env.id, amount_cents=15_000_00)

        # Export changes
        sync_payload = self.sync.export_changes()
        changes = sync_payload.get("changes", [])
        envelope_events = [e for e in changes if e.get("entity_name") == "ENVELOPE"]

        self.assertGreaterEqual(len(envelope_events), 1)

        # Import into a second database
        peer_db = Path(self.test_dir) / "peer_sync.db"
        init_database(peer_db)
        peer_conn = get_connection(peer_db)
        try:
            peer_sync = P2PSyncEngine(conn_or_path=peer_conn)
            peer_ledger = LedgerEngine(conn_or_path=peer_conn)

            merge_res = peer_sync.apply_remote_changes(sync_payload)
            self.assertGreaterEqual(merge_res["applied_count"], 1)

            peer_envelopes = peer_ledger.get_envelopes()
            self.assertEqual(len(peer_envelopes), 1)
            self.assertEqual(peer_envelopes[0]["name"], "Ремонт кухни")
            self.assertEqual(peer_envelopes[0]["current_amount_cents"], 15_000_00)
        finally:
            peer_conn.close()

    # 5. Web API Envelopes Endpoints
    def test_05_web_api_envelope_endpoints(self):
        """Verify all HTTP endpoints for envelopes with token authentication."""
        # 1. Create envelope via API
        status, resp = self._execute_http("POST", "/api/envelopes/create", {
            "name": "Новый ноутбук",
            "target_amount_rub": 120000,
            "icon": "💻",
            "color": "#8b5cf6",
            "note": "Для работы"
        }, token=self.token)
        self.assertEqual(status, 200)
        self.assertEqual(resp["status"], "success")
        env_id = resp["envelope"]["id"]

        # 2. Get envelopes list
        status, resp = self._execute_http("GET", "/api/envelopes", token=self.token)
        self.assertEqual(status, 200)
        self.assertEqual(resp["status"], "success")
        self.assertEqual(len(resp["envelopes"]), 1)
        self.assertEqual(resp["envelopes"][0]["name"], "Новый ноутбук")

        # 3. Deposit via API
        status, resp = self._execute_http("POST", "/api/envelopes/deposit", {
            "envelope_id": env_id,
            "amount_rub": 30000,
            "note": "Премия"
        }, token=self.token)
        self.assertEqual(status, 200)
        self.assertEqual(resp["status"], "success")

        # Verify balance updated
        status, resp = self._execute_http("GET", "/api/envelopes", token=self.token)
        self.assertEqual(float(resp["envelopes"][0]["current_amount_rub"]), 30000.0)

        # 4. Withdraw via API
        status, resp = self._execute_http("POST", "/api/envelopes/withdraw", {
            "envelope_id": env_id,
            "amount_rub": 10000,
            "note": "Покупка комплектующих"
        }, token=self.token)
        self.assertEqual(status, 200)
        self.assertEqual(resp["status"], "success")

        status, resp = self._execute_http("GET", "/api/envelopes", token=self.token)
        self.assertEqual(float(resp["envelopes"][0]["current_amount_rub"]), 20000.0)

        # 5. Create second envelope and transfer
        status, resp2 = self._execute_http("POST", "/api/envelopes/create", {
            "name": "Курсы английского",
            "target_amount_rub": 40000,
            "icon": "📚"
        }, token=self.token)
        env2_id = resp2["envelope"]["id"]

        status, resp = self._execute_http("POST", "/api/envelopes/transfer", {
            "from_envelope_id": env_id,
            "to_envelope_id": env2_id,
            "amount_rub": 5000,
            "note": "Перевод части"
        }, token=self.token)
        self.assertEqual(status, 200)

        status, resp = self._execute_http("GET", "/api/envelopes", token=self.token)
        env_map = {e["id"]: e for e in resp["envelopes"]}
        self.assertEqual(float(env_map[env_id]["current_amount_rub"]), 15000.0)
        self.assertEqual(float(env_map[env2_id]["current_amount_rub"]), 5000.0)

        # 6. Archive envelope
        status, resp = self._execute_http("POST", "/api/envelopes/archive", {
            "envelope_id": env2_id
        }, token=self.token)
        self.assertEqual(status, 200)

        status, resp = self._execute_http("GET", "/api/envelopes", token=self.token)
        self.assertEqual(len(resp["envelopes"]), 1)

    # 6. Persistence & Master Setup Elimination Verification
    def test_06_persistence_status_prevents_reset_to_setup(self):
        """Verify that /api/status reports has_owner=True and never forces existing families to setup-master."""
        status, resp = self._execute_http("GET", "/api/status")
        self.assertEqual(status, 200)
        self.assertTrue(resp["has_owner"], "Existing family database must always report has_owner=True")
        self.assertFalse(resp["is_locked"], "Unlocked storage must not be reported as locked")

        # Attempting setup-master on existing family with owner must be strictly rejected
        status, resp = self._execute_http("POST", "/api/setup-master", {
            "master_password": "NewPassword2026!",
            "username": "intruder",
            "display_name": "Хакер"
        })
        self.assertEqual(status, 400)
        self.assertIn("уже существует", resp["message"])


if __name__ == "__main__":
    unittest.main()
