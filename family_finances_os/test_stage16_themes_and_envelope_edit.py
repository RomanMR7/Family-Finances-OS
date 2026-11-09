"""
Stage 16 Test Suite: Themes (Light & Dark matching reference design) & Envelope Editing Integrity.
Verifies:
1. Envelope update idempotency & balance adjustment:
   - Updating envelope with identical values succeeds (fixing rowcount == 0 bug).
   - Updating current_amount_cents modifies envelope balance and records adjustment operation.
2. HTTP POST /api/envelopes/update:
   - Accepts envelope_id, name, target_amount_rub, current_amount_rub, icon, color, note.
   - Returns status: success.
3. Theme switcher integrity:
   - [data-theme="light"] and [data-theme="dark"] CSS definitions with modern banking palette.
   - #themeToggleBtn present in header with toggleTheme() JavaScript handler.
   - localStorage persistence for theme.
"""
import io
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from family_finances_os.db import init_database, EncryptedDatabaseStorage, get_connection
from family_finances_os.models import Posting, Transaction, rubles_to_cents, cents_to_rubles
from family_finances_os.ledger import LedgerEngine
from family_finances_os.auth import AuthService
from family_finances_os.web_server import FamilyFinancesHandler


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


class TestStage16ThemesAndEnvelopeEdit(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="ffos_s16_")
        self.db_path = Path(self.test_dir) / "test_stage16.db"
        self.enc_path = Path(self.test_dir) / "test_stage16.db.enc"

        init_database(self.db_path)
        self.conn = get_connection(self.db_path)
        self.auth = AuthService(conn_or_path=self.conn)
        self.owner_info = self.auth.create_owner("admin", "Глава семьи", "Family2026!")
        auth_res = self.auth.authenticate("admin", "Family2026!")
        self.token = auth_res["session_token"]

        self.ledger = LedgerEngine(conn_or_path=self.conn)
        self.ledger.seed_default_chart_of_accounts()
        self.ledger.seed_default_categories()

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

    def test_01_update_envelope_with_same_values_succeeds(self):
        """Updating envelope with identical values must return True (not fail due to SQLite 0 rows changed)."""
        env = self.ledger.create_envelope(
            name="Отпуск",
            target_amount_cents=5000000,
            icon="🏖️",
            color="#3b82f6"
        )
        self.assertIsNotNone(env.id)

        # Update with identical values
        ok = self.ledger.update_envelope(
            envelope_id=env.id,
            name="Отпуск",
            target_amount_cents=5000000,
            icon="🏖️",
            color="#3b82f6"
        )
        self.assertTrue(ok, "Updating envelope with same parameters must succeed")

    def test_02_update_envelope_balance_records_adjustment(self):
        """Updating envelope balance should adjust current_amount_cents and record operation."""
        env = self.ledger.create_envelope(
            name="Резерв",
            initial_amount_cents=1000000,
            target_amount_cents=5000000
        )
        self.assertEqual(env.current_amount_cents, 1000000)

        # Update balance to 25,000 RUB (2,500,000 cents)
        ok = self.ledger.update_envelope(
            envelope_id=env.id,
            current_amount_cents=2500000
        )
        self.assertTrue(ok)

        # Verify envelope has new balance
        updated = self.ledger.get_envelope(env.id)
        self.assertEqual(updated["current_amount_cents"], 2500000)

        # Verify operation recorded
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM envelope_operations WHERE envelope_id = ? ORDER BY rowid DESC LIMIT 1;", (env.id,))
        op = cur.fetchone()
        self.assertIsNotNone(op)
        self.assertEqual(op["amount_cents"], 1500000)

    def test_03_http_update_envelope_api(self):
        """POST /api/envelopes/update updates parameters and balance."""
        env = self.ledger.create_envelope(
            name="Авто",
            initial_amount_cents=2000000,
            target_amount_cents=10000000
        )

        code, resp = self._execute_http(
            "POST",
            "/api/envelopes/update",
            body={
                "envelope_id": env.id,
                "name": "Новое Авто",
                "target_amount_rub": "150000.00",
                "current_amount_rub": "35000.00",
                "icon": "🚗",
                "color": "#10b981",
                "note": "Копим на кроссовер"
            },
            token=self.token
        )
        self.assertEqual(code, 200)
        self.assertEqual(resp["status"], "success")

        updated = self.ledger.get_envelope(env.id)
        self.assertEqual(updated["name"], "Новое Авто")
        self.assertEqual(updated["target_amount_cents"], 15000000)
        self.assertEqual(updated["current_amount_cents"], 3500000)
        self.assertEqual(updated["icon"], "🚗")
        self.assertEqual(updated["color"], "#10b981")
        self.assertEqual(updated["note"], "Копим на кроссовер")

    def test_04_theme_switcher_and_css_variables(self):
        """Verify CSS contains [data-theme='light'] and [data-theme='dark'] with modern styling."""
        with open("family_finances_os/web_server.py", "r", encoding="utf-8") as f:
            src = f.read()

        # Check theme attributes and variables
        self.assertIn('[data-theme="light"]', src)
        self.assertIn('[data-theme="dark"]', src)
        self.assertIn('--bg', src)
        self.assertIn('--card-bg', src)
        self.assertIn('--primary', src)

        # Check toggle button and JS function
        self.assertIn('id="themeToggleBtn"', src)
        self.assertIn('function toggleTheme', src)
        self.assertIn('localStorage.getItem(\'ffos_theme\')', src)


if __name__ == "__main__":
    unittest.main()
