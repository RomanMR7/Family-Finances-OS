"""
Family Finances OS - Stage 12 Test Suite
Verification of Creation and Management of Different Types of Debts and Liabilities
(Credit Cards, Mortgages, Consumer Loans, Auto Loans, Personal Debts, BNPL Installments).
"""
import io
import json
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


class TestStage12DebtTypesCreation(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="ffos_s12_")
        self.db_path = Path(self.test_dir) / "test_stage12.db"
        self.enc_path = Path(self.test_dir) / "test_stage12.db.enc"

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

    def test_01_create_credit_card_debt(self):
        """Create a new credit card with credit limit and existing debt balance."""
        res = self.ledger.create_debt(
            name="Тинькофф Платинум",
            subtype="CREDIT_CARD",
            ownership_scope="COMMON",
            credit_limit_cents=rubles_to_cents(150000.00),
            initial_debt_cents=rubles_to_cents(35000.00),
            description="Грейс-период 55 дней"
        )
        self.assertEqual(res["status"], "success")
        acc_id = res["account_id"]

        # Verify liability account created
        acc = self.ledger.get_account_by_id(acc_id)
        self.assertIsNotNone(acc)
        self.assertEqual(acc.name, "Тинькофф Платинум")
        self.assertEqual(acc.subtype, "CREDIT_CARD")
        self.assertEqual(acc.account_type, "LIABILITY")
        self.assertEqual(acc.credit_limit_cents, rubles_to_cents(150000.00))

        # Verify balance: 35 000 ₽ debt
        self.assertEqual(self.ledger.get_account_balance_cents(acc_id), rubles_to_cents(35000.00))

        # Check debts summary
        summary = self.ledger.get_debts_summary()
        self.assertEqual(summary["credit_cards_debt_cents"], rubles_to_cents(35000.00))

    def test_02_create_mortgage_with_obligation(self):
        """Create a mortgage loan with monthly obligation automatically generated."""
        res = self.ledger.create_debt(
            name="Семейная ипотека Сбер",
            subtype="MORTGAGE",
            ownership_scope="COMMON",
            initial_debt_cents=rubles_to_cents(2500000.00),
            monthly_payment_cents=rubles_to_cents(28500.00),
            due_day=15,
            description="Квартира, ставка 6%"
        )
        self.assertEqual(res["status"], "success")
        acc_id = res["account_id"]
        obl_id = res.get("obligation_id")
        self.assertIsNotNone(obl_id, "Linked obligation must be created")

        # Verify debt summary
        summary = self.ledger.get_debts_summary()
        self.assertEqual(summary["loans_debt_cents"], rubles_to_cents(2500000.00))
        target_debt = next(d for d in summary["debts"] if d["id"] == acc_id)
        self.assertEqual(target_debt["subtype"], "MORTGAGE")
        self.assertIsNotNone(target_debt.get("linked_obligation"))
        self.assertEqual(target_debt["linked_obligation"]["amount_cents"], rubles_to_cents(28500.00))
        self.assertEqual(target_debt["linked_obligation"]["due_day"], 15)

    def test_03_create_personal_debt_with_money_receipt(self):
        """Create a personal loan (borrowed from person) and receive money to card."""
        card = self.ledger.get_account_by_code("1010")
        card_start = self.ledger.get_account_balance_cents(card.id)

        res = self.ledger.create_debt(
            name="Займ у брата Олега",
            subtype="PERSONAL_DEBT",
            ownership_scope="COMMON",
            initial_debt_cents=rubles_to_cents(100000.00),
            receive_money=True,
            destination_account_id=card.id,
            description="Без процентов, вернуть до конца года"
        )
        self.assertEqual(res["status"], "success")
        debt_acc_id = res["account_id"]

        # Card balance must increase by 100 000 ₽
        card_end = self.ledger.get_account_balance_cents(card.id)
        self.assertEqual(card_end - card_start, rubles_to_cents(100000.00))

        # Liability balance must be 100 000 ₽
        self.assertEqual(self.ledger.get_account_balance_cents(debt_acc_id), rubles_to_cents(100000.00))

    def test_04_create_bnpl_installment(self):
        """Create an installment / BNPL debt (Сплит / Долями)."""
        res = self.ledger.create_debt(
            name="Яндекс Сплит (Ноутбук)",
            subtype="INSTALLMENT_BNPL",
            ownership_scope="COMMON",
            initial_debt_cents=rubles_to_cents(60000.00),
            monthly_payment_cents=rubles_to_cents(15000.00),
            due_day=5,
            description="4 платежа раз в 2 недели"
        )
        self.assertEqual(res["status"], "success")
        acc_id = res["account_id"]

        summary = self.ledger.get_debts_summary()
        target = next(d for d in summary["debts"] if d["id"] == acc_id)
        self.assertEqual(target["subtype"], "INSTALLMENT_BNPL")
        self.assertEqual(target["debt_cents"], rubles_to_cents(60000.00))

    def test_05_http_api_create_and_archive_debt(self):
        """Verify POST /api/debts/create and POST /api/debts/archive HTTP endpoints."""
        status, resp = self._execute_http(
            "POST", "/api/debts/create",
            {
                "name": "Автокредит Geely",
                "subtype": "AUTO_LOAN",
                "ownership_scope": "COMMON",
                "initial_debt_rub": 850000.0,
                "monthly_payment_rub": 22000.0,
                "due_day": 20,
                "description": "Автосалон Восток"
            },
            token=self.token
        )
        self.assertEqual(status, 200)
        self.assertEqual(resp["status"], "success")
        acc_id = resp["account"]["id"]

        # Check via GET /api/debts
        status_get, data_get = self._execute_http("GET", "/api/debts", token=self.token)
        self.assertEqual(status_get, 200)
        found = any(d["id"] == acc_id for d in data_get["debts"])
        self.assertTrue(found, "Created auto loan must appear in /api/debts")

        # Archive debt
        status_arch, resp_arch = self._execute_http(
            "POST", "/api/debts/archive",
            {"account_id": acc_id},
            token=self.token
        )
        self.assertEqual(status_arch, 200)
        self.assertEqual(resp_arch["status"], "success")

        # Must not appear in active debts
        status_get2, data_get2 = self._execute_http("GET", "/api/debts", token=self.token)
        found2 = any(d["id"] == acc_id for d in data_get2["debts"])
        self.assertFalse(found2, "Archived debt must not appear in active debts")


if __name__ == "__main__":
    unittest.main()
