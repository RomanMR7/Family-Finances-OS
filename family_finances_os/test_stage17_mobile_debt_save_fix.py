"""
Unit and integration tests for Stage 17:
Mobile Debt Save Fix, Viewport Scroll, Russian Comma/Space Number Parsing,
Dropdown Dismissal, Z-Index Hierarchy, and Category Resilience.
"""
import io
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from family_finances_os.db import init_database, EncryptedDatabaseStorage, get_connection
from family_finances_os.models import rubles_to_cents, cents_to_rubles
from family_finances_os.ledger import LedgerEngine, DEBT_CATEGORY_MAP
from family_finances_os.auth import AuthService
from family_finances_os.web_server import FamilyFinancesHandler, safe_float


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


class TestStage17MobileDebtSave(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="ffos_s17_")
        self.db_path = Path(self.test_dir) / "test_stage17.db"
        self.enc_path = Path(self.test_dir) / "test_stage17.db.enc"

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

    def test_models_rubles_to_cents_mobile_formatting(self):
        """Verify rubles_to_cents handles Russian keyboard commas, spaces, currency symbols, and empty states."""
        # Standard numbers
        self.assertEqual(rubles_to_cents(100), 10000)
        self.assertEqual(rubles_to_cents(100.50), 10050)
        self.assertEqual(rubles_to_cents("100.50"), 10050)

        # Russian mobile keypad comma
        self.assertEqual(rubles_to_cents("50000,00"), 5000000)
        self.assertEqual(rubles_to_cents("1250,99"), 125099)
        self.assertEqual(rubles_to_cents("24,8"), 2480)

        # Spaces and non-breaking spaces
        self.assertEqual(rubles_to_cents("50 000"), 5000000)
        self.assertEqual(rubles_to_cents("50\xa0000"), 5000000)
        self.assertEqual(rubles_to_cents("1 250 000,50"), 125000050)
        self.assertEqual(rubles_to_cents("165 000 ₽"), 16500000)

        # Edge cases & empty inputs
        self.assertEqual(rubles_to_cents(None), 0)
        self.assertEqual(rubles_to_cents(""), 0)
        self.assertEqual(rubles_to_cents("   "), 0)
        for invalid in ("invalid_text", "NaN", "Infinity"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                rubles_to_cents(invalid)

    def test_safe_float_backend(self):
        """Verify safe_float parses various inputs and defaults safely."""
        self.assertEqual(safe_float("50 000,50"), 50000.5)
        self.assertEqual(safe_float("165 000 ₽"), 165000.0)
        self.assertEqual(safe_float("24,8"), 24.8)
        self.assertEqual(safe_float("3,0"), 3.0)
        self.assertEqual(safe_float(None, 24.8), 24.8)
        self.assertEqual(safe_float("", 3.0), 3.0)
        self.assertEqual(safe_float("invalid", 36.0), 36.0)
        self.assertEqual(safe_float(120, 0), 120.0)

    def test_ledger_create_debt_obligation_category_resilience(self):
        """Verify create_debt creates obligation even if categories were missing."""
        cursor = self.conn.cursor()
        # Delete specific credit card category to test self-healing
        cursor.execute("DELETE FROM categories WHERE id = 'cat_debts_credit_card';")
        self.conn.commit()

        res = self.ledger.create_debt(
            name="Кредитная СберКарта ТП-1001",
            subtype="CREDIT_CARD",
            credit_limit_cents=16500000,
            initial_debt_cents=5000000,
            monthly_payment_cents=300000,
            due_day=15,
            interest_rate_percent=24.8,
            grace_period_days=120
        )
        self.assertEqual(res["status"], "success")
        self.assertIsNotNone(res["obligation_id"])

        cursor.execute("SELECT * FROM obligations WHERE id = ?;", (res["obligation_id"],))
        obl = cursor.fetchone()
        self.assertIsNotNone(obl)
        self.assertEqual(obl["amount_cents"], 300000)
        self.assertEqual(obl["due_day"], 15)

    def test_api_debts_create_with_mobile_russian_comma_and_spaces(self):
        """Test creating debt via HTTP API with Russian mobile comma and spaces in numbers."""
        payload = {
            "name": "СберКарта 120 Дней Мобильная",
            "subtype": "CREDIT_CARD",
            "ownership_scope": "COMMON",
            "credit_limit_rub": "165 000,00",
            "initial_debt_rub": "50 000,50",
            "monthly_payment_rub": "3 000,00",
            "due_day": 15,
            "interest_rate_percent": "24,8",
            "grace_period_days": "120",
            "grace_due_date": "2026-11-30",
            "min_payment_percent": "3,0",
            "late_penalty_rate_percent": "36,0",
            "description": "Тест мобильного сохранения"
        }
        status, data = self._execute_http("POST", "/api/debts/create", body=payload, token=self.token)
        self.assertEqual(status, 200)
        self.assertEqual(data["status"], "success")
        self.assertIn("account_id", data)
        acc_id = data["account_id"]

        # Verify via GET /api/debts
        status_get, debts_data = self._execute_http("GET", "/api/debts", token=self.token)
        self.assertEqual(status_get, 200)
        saved = next((d for d in debts_data["debts"] if d["id"] == acc_id), None)
        self.assertIsNotNone(saved)
        self.assertEqual(saved["credit_limit_rub"], "165000.00")
        self.assertEqual(saved["debt_rub"], "50000.50")
        self.assertEqual(saved["banking"]["interest_rate_percent"], 24.8)
        self.assertEqual(saved["banking"]["min_payment_percent"], 3.0)
        self.assertEqual(saved["banking"]["late_penalty_rate_percent"], 36.0)

    def test_html_modal_and_js_mobile_invariants(self):
        """Verify web_server.py contains all mobile layout, JS helpers, and CSS classes."""
        server_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "web_server.py"))
        with open(server_path, "r", encoding="utf-8") as f:
            html = f.read()

        # 1. z-index 100000 on modalNewDebt
        self.assertIn('id="modalNewDebt"', html)
        self.assertIn('z-index: 100000;', html)

        # 2. .debt-type-grid class and styles
        self.assertIn('class="debt-type-grid"', html)
        self.assertIn('.debt-type-grid {', html)
        self.assertIn('.debt-type-btn {', html)
        self.assertIn('.debt-type-btn.active {', html)

        # 3. Mobile modal responsive viewport scroll fix
        self.assertIn('#modalNewDebt, #modalEditTx', html)
        self.assertIn('align-items: flex-start !important;', html)
        self.assertIn('-webkit-overflow-scrolling: touch !important;', html)

        # 4. JS parseMobileFloat function
        self.assertIn('function parseMobileFloat(', html)

        # 5. Dropdown dismissal when opening modal
        self.assertIn("document.querySelectorAll('.category-dropdown-menu').forEach", html)

        # 6. Button feedback on submit
        self.assertIn('btn.innerText = \'⏳ Сохранение...\'', html)


if __name__ == "__main__":
    unittest.main()
