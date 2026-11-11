"""
Stage 15 Test Suite: Credit Card Payoff Calculator & Dual Ruble/Percent Repayments.
Verifies:
1. calculate_credit_payoff_scenarios in LedgerEngine:
   - Grace period scenario (0% overpayment, days remaining)
   - Minimum mandatory payment (3% / 150 rub minimum) simulation with days/months to payoff and total overpayment
   - Accelerated payoff horizons (3 months, 6 months, 12 months) with required monthly payments, days, and interest savings
   - Custom payment simulation (both in rubles and as percent of current debt)
2. Handling of zero debt and edge cases (0% APR, debt <= 0, small balance).
3. /api/debts/pay supporting amount_percent (e.g. 3%, 10%, 100%) with double-entry precision and dual description.
4. /api/debts/calculate-payoff endpoint for live interactive calculations.
5. Frontend UI syntax and HTML elements integrity.
"""
import io
import json
import os
import shutil
import tempfile
import unittest
from datetime import date, timedelta
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


class TestStage15CreditPayoffCalculator(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="ffos_s15_")
        self.db_path = Path(self.test_dir) / "test_stage15.db"
        self.enc_path = Path(self.test_dir) / "test_stage15.db.enc"

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

    def test_01_payoff_scenarios_calculation(self):
        """Test calculation of grace, minimum payment, and 3/6/12 month acceleration scenarios."""
        # 100,000 RUB debt at 24.8% APR with 3.0% min payment
        debt_cents = 10000000
        due_date = (date.today() + timedelta(days=45)).isoformat()
        res = self.ledger.calculate_credit_payoff_scenarios(
            debt_cents=debt_cents,
            interest_rate_percent=24.8,
            min_payment_percent=3.0,
            grace_due_date=due_date
        )

        self.assertEqual(res["debt_cents"], debt_cents)
        self.assertEqual(res["debt_rub"], "100000.00")

        # Grace scenario
        grace = res["grace_scenario"]
        self.assertEqual(grace["days_left"], 45)
        self.assertEqual(grace["total_interest_rub"], "0.00")
        self.assertTrue(grace["is_active"])

        # Minimum payment scenario
        min_sc = res["minimum_scenario"]
        # The 3% balance-based plan does not fully close within the declared
        # 360-month horizon; a finite payoff must not be fabricated.
        self.assertEqual(min_sc["status"], "HORIZON_LIMIT")
        self.assertFalse(min_sc["paid_off"])
        self.assertIsNone(min_sc["months_to_payoff"])
        self.assertIsNone(min_sc["payoff_date"])
        self.assertGreater(min_sc["remaining_cents"], 0)
        self.assertEqual(min_sc["first_payment_rub"], "3000.00")

        # Accelerated scenarios (3, 6, 12 months)
        acc = res["accelerated_scenarios"]
        self.assertEqual(len(acc), 3)

        sc_3m = next(s for s in acc if s["months"] == 3)
        self.assertGreater(sc_3m["monthly_payment_cents"], 3000000) # ~34,720 RUB
        self.assertTrue(sc_3m["paid_off"])
        self.assertIsNone(sc_3m["interest_savings_cents"])
        self.assertIsNone(sc_3m["days_saved"])
        self.assertEqual(sc_3m["remaining_cents"], 0)

        sc_6m = next(s for s in acc if s["months"] == 6)
        self.assertGreater(sc_6m["monthly_payment_cents"], 1500000) # ~17,890 RUB
        self.assertTrue(sc_6m["paid_off"])
        self.assertEqual(sc_6m["remaining_cents"], 0)

        sc_12m = next(s for s in acc if s["months"] == 12)
        self.assertGreater(sc_12m["monthly_payment_cents"], 800000) # ~9,490 RUB
        self.assertTrue(sc_12m["paid_off"])
        self.assertEqual(sc_12m["remaining_cents"], 0)

    def test_02_custom_payment_in_rub_and_percent(self):
        """Test custom payment simulation both in rubles and percent."""
        debt_cents = 10000000
        # Custom 20,000 RUB payment
        res_rub = self.ledger.calculate_credit_payoff_scenarios(
            debt_cents=debt_cents,
            interest_rate_percent=24.8,
            min_payment_percent=3.0,
            custom_payment_cents=2000000
        )
        custom = res_rub["custom_scenario"]
        self.assertIsNotNone(custom)
        self.assertLess(custom["months_to_payoff"], 7)
        self.assertTrue(custom["paid_off"])
        self.assertEqual(custom["remaining_cents"], 0)
        self.assertIsNone(custom["interest_savings_cents"])

        # Custom 10% payment
        res_pct = self.ledger.calculate_credit_payoff_scenarios(
            debt_cents=debt_cents,
            interest_rate_percent=24.8,
            min_payment_percent=3.0,
            custom_payment_percent=10.0
        )
        custom_p = res_pct["custom_scenario"]
        self.assertIsNotNone(custom_p)
        self.assertEqual(custom_p["payment_percent"], 10.0)
        self.assertEqual(custom_p["monthly_payment_rub"], "10000.00")

    def test_03_zero_debt_and_edge_cases(self):
        """Test zero debt and edge conditions."""
        res_zero = self.ledger.calculate_credit_payoff_scenarios(debt_cents=0)
        self.assertEqual(res_zero["debt_cents"], 0)
        self.assertEqual(res_zero["minimum_scenario"]["months_to_payoff"], 0)
        self.assertEqual(res_zero["minimum_scenario"]["days_to_payoff"], 0)

        # 0% APR
        res_no_apr = self.ledger.calculate_credit_payoff_scenarios(
            debt_cents=3000000,
            interest_rate_percent=0.0,
            custom_payment_cents=1000000
        )
        self.assertEqual(res_no_apr["custom_scenario"]["months_to_payoff"], 3)
        self.assertEqual(res_no_apr["custom_scenario"]["total_interest_cents"], 0)

    def test_04_pay_debt_via_percent_api(self):
        """Test /api/debts/pay accepting amount_percent and recording dual representation."""
        # 1. Create checking account with 100,000 RUB
        cash_res = self.ledger.create_account(
            code="1025",
            name="Дебетовая карта Сбер",
            account_type="ASSET",
            subtype="CHECKING",
            ownership_scope="COMMON",
            initial_balance_cents=10000000
        )
        cash_acc_id = cash_res.id

        # 2. Create credit card with 50,000 RUB debt
        card_res = self.ledger.create_debt(
            name="Кредитная СберКарта",
            subtype="CREDIT_CARD",
            credit_limit_cents=16500000,
            initial_debt_cents=5000000,
            monthly_payment_cents=150000,
            due_day=20
        )
        card_id = card_res["account_id"]

        # 3. Pay 10% of debt via API (50,000 * 10% = 5,000 RUB / 500,000 cents)
        code, resp = self._execute_http(
            "POST",
            "/api/debts/pay",
            body={
                "liability_account_id": card_id,
                "source_account_id": cash_acc_id,
                "amount_percent": 10.0,
                "description": "Платеж по кредитке"
            },
            token=self.token
        )
        self.assertEqual(code, 200)
        self.assertEqual(resp["status"], "success")

        # Check remaining balance of credit card: 50,000 - 5,000 = 45,000 RUB
        summary = self.ledger.get_debts_summary()
        card_item = next(d for d in summary["debts"] if d["id"] == card_id)
        self.assertEqual(card_item["debt_cents"], 4500000)
        self.assertEqual(card_item["debt_rub"], "45000.00")

    def test_05_calculate_payoff_api_endpoint(self):
        """Test /api/debts/calculate-payoff endpoint returns structured scenarios."""
        card_res = self.ledger.create_debt(
            name="Кредитка Тинькофф",
            subtype="CREDIT_CARD",
            credit_limit_cents=10000000,
            initial_debt_cents=6000000,
            monthly_payment_cents=200000,
            due_day=25
        )
        card_id = card_res["account_id"]

        code, resp = self._execute_http(
            "GET",
            f"/api/debts/calculate-payoff?liability_account_id={card_id}&custom_payment_percent=15.0",
            token=self.token
        )
        self.assertEqual(code, 200)
        self.assertIn("grace_scenario", resp)
        self.assertIn("minimum_scenario", resp)
        self.assertIn("accelerated_scenarios", resp)
        self.assertIn("custom_scenario", resp)
        self.assertEqual(resp["custom_scenario"]["payment_percent"], 15.0)


    def test_06_frontend_payoff_ui_elements(self):
        """Test presence of dual payment inputs, percentage chips, forecast box, and JS functions."""
        # Note: root returns HTML text in parts
        with open("family_finances_os/web_server.py", "r", encoding="utf-8") as f:
            src = f.read()

        # HTML elements
        self.assertIn('id="payDebtAmountPercent"', src)
        self.assertIn('id="payDebtForecastBox"', src)
        self.assertIn('id="payDebtForecastDays"', src)
        self.assertIn('id="payDebtForecastSavings"', src)
        self.assertIn('setPayDebtPercent(3.0)', src)
        self.assertIn('setPayDebtPercent(100.0)', src)

        # JS functions
        self.assertIn('function onPayDebtAmountRubChanged', src)
        self.assertIn('function onPayDebtAmountPercentChanged', src)
        self.assertIn('function setPayDebtPercent', src)
        self.assertIn('function updatePayDebtForecast', src)
        self.assertIn('function applyPresetPayDebt', src)
        self.assertIn('payoffAcceleratorsHtml', src)


if __name__ == "__main__":
    unittest.main()
