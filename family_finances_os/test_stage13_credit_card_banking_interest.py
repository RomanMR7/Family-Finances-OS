"""
Test Stage 13: Credit Card Banking System, Grace Period Tracking,
APR Interest Simulation, and Overdue Penalty Warnings according to
Russian Bank Standards (PAO Sberbank contract TP-1001 specification:
165 000 ₽ limit, 24.8% APR, 120 days grace, 3% minimum mandatory payment,
36.0% overdue penalty rate).
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
from family_finances_os.models import rubles_to_cents, cents_to_rubles
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


class TestStage13CreditCardBankingInterest(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="ffos_s13_")
        self.db_path = Path(self.test_dir) / "test_stage13.db"
        self.enc_path = Path(self.test_dir) / "test_stage13.db.enc"

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

    def test_01_calculate_credit_card_banking_metrics_normal_grace(self):
        """
        Verify mathematical accuracy of banking calculations when card is within grace:
        50 000 ₽ debt, 165 000 ₽ limit, 24.8% APR, 3% min payment, 36.0% overdue penalty.
        Due date is 20 days ahead.
        """
        today = date.today()
        due_date = (today + timedelta(days=20)).isoformat()
        debt_cents = 5_000_000  # 50 000.00 ₽
        limit_cents = 16_500_000  # 165 000.00 ₽

        metrics = self.ledger.calculate_credit_card_banking_metrics(
            debt_cents=debt_cents,
            credit_limit_cents=limit_cents,
            interest_rate_percent=24.8,
            grace_period_days=120,
            grace_due_date=due_date,
            min_payment_percent=3.0,
            late_penalty_rate_percent=36.0,
            as_of_date=today.isoformat()
        )

        # 3% min payment on 50 000 ₽ = 1 500.00 ₽ (150 000 cents)
        self.assertEqual(metrics["min_payment_cents"], 150_000)
        self.assertEqual(metrics["min_payment_rub"], 1500.0)
        self.assertEqual(metrics["days_remaining"], 20)
        self.assertEqual(metrics["status"], "GRACE_ACTIVE")
        self.assertFalse(metrics["is_urgent"])
        self.assertFalse(metrics["is_overdue"])

        # Overdue simulation for 30 days:
        # 50 000 * 24.8 / 100 / 365 * 30 = 1019.18 ₽ (101 918 cents)
        self.assertAlmostEqual(metrics["simulation_30d_interest_rub"], 1019.18, delta=1.0)
        # 50 000 * 36.0 / 100 / 365 * 30 = 1479.45 ₽ (147 945 cents)
        self.assertAlmostEqual(metrics["simulation_30d_penalty_rub"], 1479.45, delta=1.0)
        # Total payable if overdue for 30 days:
        expected_total = 50000.0 + metrics["simulation_30d_interest_rub"] + metrics["simulation_30d_penalty_rub"]
        self.assertAlmostEqual(metrics["simulation_30d_total_rub"], expected_total, delta=0.5)

    def test_02_calculate_credit_card_banking_metrics_expiring_soon(self):
        """
        Verify warning state when due date is <= 5 days away.
        """
        today = date.today()
        due_date = (today + timedelta(days=3)).isoformat()
        debt_cents = 3_000_000  # 30 000.00 ₽

        metrics = self.ledger.calculate_credit_card_banking_metrics(
            debt_cents=debt_cents,
            credit_limit_cents=10_000_000,
            interest_rate_percent=24.8,
            grace_due_date=due_date,
            min_payment_percent=3.0,
            as_of_date=today.isoformat()
        )

        self.assertEqual(metrics["days_remaining"], 3)
        self.assertEqual(metrics["status"], "PAYMENT_DUE_SOON")
        self.assertTrue(metrics["is_urgent"])
        self.assertFalse(metrics["is_overdue"])
        self.assertIn("Срочно", metrics["warning_message"])

    def test_03_calculate_credit_card_banking_metrics_overdue(self):
        """
        Verify penalty and interest accumulation when payment is overdue (e.g. 5 days overdue).
        """
        today = date.today()
        due_date = (today - timedelta(days=5)).isoformat()
        debt_cents = 6_000_000  # 60 000.00 ₽

        metrics = self.ledger.calculate_credit_card_banking_metrics(
            debt_cents=debt_cents,
            credit_limit_cents=16_500_000,
            interest_rate_percent=24.8,
            grace_due_date=due_date,
            min_payment_percent=3.0,
            late_penalty_rate_percent=36.0,
            as_of_date=today.isoformat()
        )

        self.assertEqual(metrics["days_remaining"], -5)
        self.assertEqual(metrics["overdue_days"], 5)
        self.assertEqual(metrics["status"], "OVERDUE")
        self.assertTrue(metrics["is_urgent"])
        self.assertTrue(metrics["is_overdue"])

        # Accrued for 5 days of overdue:
        # Interest: 60 000 * 0.248 / 365 * 5 = 203.84 ₽
        self.assertGreater(metrics["accrued_overdue_interest_rub"], 0)
        # Penalty: 60 000 * 0.360 / 365 * 5 = 295.89 ₽
        self.assertGreater(metrics["accrued_overdue_penalty_rub"], 0)
        self.assertGreater(metrics["current_debt_with_accruals_rub"], 60000.0)

    def test_04_create_debt_credit_card_with_banking_parameters(self):
        """
        Verify LedgerEngine.create_debt stores credit card banking settings in account
        and get_debts_summary() returns enriched banking details.
        """
        today = date.today()
        due_date = (today + timedelta(days=4)).isoformat()

        res = self.ledger.create_debt(
            name="Кредитная СберКарта ТП-1001",
            subtype="CREDIT_CARD",
            credit_limit_cents=16_500_000,
            initial_debt_cents=4_500_000,  # 45 000.00 ₽
            interest_rate_percent=24.8,
            grace_period_days=120,
            grace_due_date=due_date,
            min_payment_percent=3.0,
            late_penalty_rate_percent=36.0,
            description="Договор Сбербанка 165 000 ₽"
        )
        self.assertEqual(res["status"], "success")
        acc_id = res["account_id"]

        summary = self.ledger.get_debts_summary()
        self.assertEqual(float(summary["total_debt_rub"]), 45000.0)
        self.assertTrue(summary["has_urgent_card_payment"])

        card = next((d for d in summary["debts"] if d["id"] == acc_id), None)
        self.assertIsNotNone(card)
        self.assertIn("banking", card)
        b = card["banking"]
        self.assertEqual(b["interest_rate_percent"], 24.8)
        self.assertEqual(b["grace_period_days"], 120)
        self.assertEqual(b["grace_due_date"], due_date)
        self.assertEqual(b["min_payment_rub"], 1350.0)  # 3% of 45 000 ₽ = 1 350.00 ₽
        self.assertEqual(b["status"], "PAYMENT_DUE_SOON")
        self.assertGreater(b["simulation_30d_total_rub"], 45000.0)

    def test_05_http_api_create_and_update_credit_card_settings(self):
        """
        Verify HTTP endpoints for creating credit card with banking parameters
        and updating them dynamically via /api/debts/update-card-settings.
        """
        today = date.today()
        due_date = (today + timedelta(days=15)).isoformat()

        # 1. Create card via API
        status, data = self._execute_http("POST", "/api/debts/create", {
            "name": "СберКарта 120 дней",
            "subtype": "CREDIT_CARD",
            "credit_limit_rub": 165000.0,
            "initial_debt_rub": 50000.0,
            "interest_rate_percent": 24.8,
            "grace_period_days": 120,
            "grace_due_date": due_date,
            "min_payment_percent": 3.0,
            "late_penalty_rate_percent": 36.0,
            "description": "Карта из договора"
        }, token=self.token)
        self.assertEqual(status, 200)
        acc_id = data["account_id"]

        # 2. Check /api/debts returns banking info
        status, debts_data = self._execute_http("GET", "/api/debts", token=self.token)
        self.assertEqual(status, 200)
        card = next(d for d in debts_data["debts"] if d["id"] == acc_id)
        self.assertEqual(card["banking"]["min_payment_rub"], 1500.0)
        self.assertEqual(card["banking"]["days_remaining"], 15)
        self.assertEqual(card["banking"]["status"], "GRACE_ACTIVE")

        # 3. Update settings via /api/debts/update-card-settings
        new_due_date = (today + timedelta(days=2)).isoformat()
        status, upd_data = self._execute_http("POST", "/api/debts/update-card-settings", {
            "account_id": acc_id,
            "interest_rate_percent": 38.8,  # Increased rate from contract
            "grace_period_days": 120,
            "grace_due_date": new_due_date,
            "min_payment_percent": 3.0,
            "late_penalty_rate_percent": 36.0,
            "credit_limit_rub": 200000.0
        }, token=self.token)
        self.assertEqual(status, 200)

        # 4. Verify updated state in /api/debts
        status, debts_data2 = self._execute_http("GET", "/api/debts", token=self.token)
        self.assertEqual(status, 200)
        card2 = next(d for d in debts_data2["debts"] if d["id"] == acc_id)
        self.assertEqual(card2["banking"]["interest_rate_percent"], 38.8)
        self.assertEqual(card2["banking"]["grace_due_date"], new_due_date)
        self.assertEqual(card2["banking"]["days_remaining"], 2)
        self.assertEqual(card2["banking"]["status"], "PAYMENT_DUE_SOON")
        self.assertTrue(card2["banking"]["is_urgent"])
        self.assertEqual(float(card2["credit_limit_rub"]), 200000.0)


if __name__ == "__main__":
    unittest.main()
