"""
Family Finances OS - Stage 11 Test Suite
Verification of Past Months Editing (Редактирование прошлых месяцев),
Backdated Transactions, Transaction Updates, and Month Navigation.
"""
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from family_finances_os.db import init_database, EncryptedDatabaseStorage, get_connection
from family_finances_os.models import Posting, Transaction
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


class TestStage11PastMonthsEditing(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="ffos_s11_")
        self.db_path = Path(self.test_dir) / "test_stage11.db"
        self.enc_path = Path(self.test_dir) / "test_stage11.db.enc"

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

    def test_01_create_backdated_transaction(self):
        """Verify recording an expense with a past date (e.g. in October 2026)."""
        card = self.ledger.get_account_by_code("1010")
        groceries_acc = self.ledger.get_account_by_code("5010")
        flat_cats = self.ledger.get_flat_categories("EXPENSE")
        cat_id = flat_cats[0]["id"]

        status, resp = self._execute_http(
            "POST", "/api/transaction/create",
            {
                "tx_type": "EXPENSE",
                "account_id": card.id,
                "category_account_id": groceries_acc.id,
                "category_id": cat_id,
                "amount_rub": 2500.0,
                "description": "Супермаркет за прошлый месяц",
                "tx_date": "2026-10-14"
            },
            token=self.token
        )
        self.assertEqual(status, 200)
        self.assertEqual(resp["status"], "success")
        tx_id = resp["transaction_id"]

        # Verify in database
        cur = self.conn.cursor()
        cur.execute("SELECT tx_date, description, tx_type FROM transactions WHERE id = ?", (tx_id,))
        row = cur.fetchone()
        self.assertEqual(row["tx_date"], "2026-10-14")
        self.assertEqual(row["description"], "Супермаркет за прошлый месяц")

    def test_02_update_transaction_details(self):
        """Verify update_transaction modifies date, amount, category, and account while preserving double entry."""
        card1 = self.ledger.get_account_by_code("1010")
        card2 = self.ledger.get_account_by_code("1011")
        expense_acc = self.ledger.get_account_by_code("5010")
        flat_cats = self.ledger.get_flat_categories("EXPENSE")
        cat1_id = flat_cats[0]["id"]
        cat2_id = flat_cats[1]["id"]

        # Create initial transaction
        tx = Transaction(
            id="tx-edit-001",
            tx_date="2026-10-10",
            tx_type="EXPENSE",
            description="Старое описание",
            postings=[
                Posting(id="p-edit-1", transaction_id="tx-edit-001", account_id=expense_acc.id, amount_cents=100000, posting_type="DEBIT", category_id=cat1_id),
                Posting(id="p-edit-2", transaction_id="tx-edit-001", account_id=card1.id, amount_cents=100000, posting_type="CREDIT")
            ]
        )
        self.ledger.record_transaction(tx)

        # Update transaction
        ok = self.ledger.update_transaction(
            transaction_id="tx-edit-001",
            tx_date="2026-09-25",
            amount_cents=175000,
            description="Обновленное описание сентября",
            category_id=cat2_id,
            account_id=card2.id
        )
        self.assertTrue(ok)

        # Verify updated header
        cur = self.conn.cursor()
        cur.execute("SELECT tx_date, description FROM transactions WHERE id = 'tx-edit-001'")
        header = cur.fetchone()
        self.assertEqual(header["tx_date"], "2026-09-25")
        self.assertEqual(header["description"], "Обновленное описание сентября")

        # Verify updated postings and double-entry balance
        cur.execute("SELECT account_id, amount_cents, posting_type, category_id FROM postings WHERE transaction_id = 'tx-edit-001'")
        postings = cur.fetchall()
        self.assertEqual(len(postings), 2)
        debit = next(p for p in postings if p["posting_type"] == "DEBIT")
        credit = next(p for p in postings if p["posting_type"] == "CREDIT")
        self.assertEqual(debit["amount_cents"], 175000)
        self.assertEqual(credit["amount_cents"], 175000)
        self.assertEqual(debit["category_id"], cat2_id)
        self.assertEqual(credit["account_id"], card2.id)

    def test_03_void_delete_transaction(self):
        """Verify voiding/deleting an operation removes it from active calculations."""
        card = self.ledger.get_account_by_code("1010")
        expense_acc = self.ledger.get_account_by_code("5010")

        tx = Transaction(
            id="tx-void-001",
            tx_date="2026-10-05",
            tx_type="EXPENSE",
            description="Ошибочная операция",
            postings=[
                Posting(id="p-void-1", transaction_id="tx-void-001", account_id=expense_acc.id, amount_cents=50000, posting_type="DEBIT"),
                Posting(id="p-void-2", transaction_id="tx-void-001", account_id=card.id, amount_cents=50000, posting_type="CREDIT")
            ]
        )
        self.ledger.record_transaction(tx)

        ok = self.ledger.void_transaction("tx-void-001", reason="Удалено пользователем")
        self.assertTrue(ok)

        cur = self.conn.cursor()
        cur.execute("SELECT is_voided, voided_reason FROM transactions WHERE id = 'tx-void-001'")
        row = cur.fetchone()
        self.assertEqual(row["is_voided"], 1)
        self.assertEqual(row["voided_reason"], "Удалено пользователем")

    def test_04_transactions_query_by_month(self):
        """Verify /api/transactions?month=YYYY-MM filters transactions by specified month."""
        card = self.ledger.get_account_by_code("1010")
        expense_acc = self.ledger.get_account_by_code("5010")

        for month_str, desc, amount in [("2026-09-12", "Сентябрьская трата", 100000),
                                        ("2026-10-18", "Октябрьская трата", 200000),
                                        ("2026-11-02", "Ноябрьская трата", 300000)]:
            self.ledger.record_transaction(Transaction(
                id=f"tx-{month_str}",
                tx_date=month_str,
                tx_type="EXPENSE",
                description=desc,
                postings=[
                    Posting(id=f"p1-{month_str}", transaction_id=f"tx-{month_str}", account_id=expense_acc.id, amount_cents=amount, posting_type="DEBIT"),
                    Posting(id=f"p2-{month_str}", transaction_id=f"tx-{month_str}", account_id=card.id, amount_cents=amount, posting_type="CREDIT")
                ]
            ))

        # Query October
        status, data = self._execute_http("GET", "/api/transactions?month=2026-10", token=self.token)
        self.assertEqual(status, 200)
        tx_list = data["transactions"]
        self.assertEqual(len(tx_list), 1)
        self.assertEqual(tx_list[0]["description"], "Октябрьская трата")

        # Verify available months list
        self.assertIn("available_months", data)
        self.assertIn("2026-10", data["available_months"])
        self.assertIn("2026-09", data["available_months"])
        self.assertIn("2026-11", data["available_months"])

    def test_05_analytics_for_past_month(self):
        """Verify /api/analytics/summary?period=YYYY-MM computes analytics strictly for past month."""
        card = self.ledger.get_account_by_code("1010")
        expense_acc = self.ledger.get_account_by_code("5010")
        income_acc = self.ledger.get_account_by_code("4010")

        # October income & expense
        self.ledger.record_transaction(Transaction(
            id="tx-oct-inc",
            tx_date="2026-10-05",
            tx_type="INCOME",
            description="Зарплата октябрь",
            postings=[
                Posting(id="p-oi-1", transaction_id="tx-oct-inc", account_id=card.id, amount_cents=10000000, posting_type="DEBIT"),
                Posting(id="p-oi-2", transaction_id="tx-oct-inc", account_id=income_acc.id, amount_cents=10000000, posting_type="CREDIT")
            ]
        ))
        self.ledger.record_transaction(Transaction(
            id="tx-oct-exp",
            tx_date="2026-10-15",
            tx_type="EXPENSE",
            description="Траты октябрь",
            postings=[
                Posting(id="p-oe-1", transaction_id="tx-oct-exp", account_id=expense_acc.id, amount_cents=4000000, posting_type="DEBIT"),
                Posting(id="p-oe-2", transaction_id="tx-oct-exp", account_id=card.id, amount_cents=4000000, posting_type="CREDIT")
            ]
        ))

        # November expense (should not bleed into October analytics)
        self.ledger.record_transaction(Transaction(
            id="tx-nov-exp",
            tx_date="2026-11-01",
            tx_type="EXPENSE",
            description="Траты ноябрь",
            postings=[
                Posting(id="p-ne-1", transaction_id="tx-nov-exp", account_id=expense_acc.id, amount_cents=5000000, posting_type="DEBIT"),
                Posting(id="p-ne-2", transaction_id="tx-nov-exp", account_id=card.id, amount_cents=5000000, posting_type="CREDIT")
            ]
        ))

        status, data = self._execute_http("GET", "/api/analytics/summary?period=2026-10", token=self.token)
        self.assertEqual(status, 200)
        self.assertEqual(data["total_income_cents"], 10000000)
        self.assertEqual(data["total_expense_cents"], 4000000)
        self.assertEqual(data["net_savings_cents"], 6000000)
        self.assertEqual(float(data["total_income_rub"].replace(" ", "")), 100000.0)
        self.assertEqual(float(data["total_expense_rub"].replace(" ", "")), 40000.0)

    def test_06_http_api_transaction_update_and_delete(self):
        """Verify HTTP endpoints for updating and deleting transactions."""
        card1 = self.ledger.get_account_by_code("1010")
        card2 = self.ledger.get_account_by_code("1011")
        flat_cats = self.ledger.get_flat_categories("EXPENSE")
        cat_id = flat_cats[0]["id"]
        cat_acc_id = self.ledger.get_account_by_code("5010").id

        # Create
        status, resp = self._execute_http(
            "POST", "/api/transaction/create",
            {
                "tx_type": "EXPENSE",
                "account_id": card1.id,
                "category_account_id": cat_acc_id,
                "category_id": cat_id,
                "amount_rub": 1200.0,
                "description": "Первоначальная операция",
                "tx_date": "2026-10-01"
            },
            token=self.token
        )
        self.assertEqual(status, 200)
        tx_id = resp["transaction_id"]

        # Update via HTTP
        status_up, resp_up = self._execute_http(
            "POST", "/api/transactions/update",
            {
                "transaction_id": tx_id,
                "amount_rub": 1850.50,
                "description": "Скорректированное описание",
                "tx_date": "2026-09-30",
                "account_id": card2.id,
                "category_id": cat_id
            },
            token=self.token
        )
        self.assertEqual(status_up, 200)
        self.assertEqual(resp_up["status"], "success")

        # Delete via HTTP
        status_del, resp_del = self._execute_http(
            "POST", "/api/transactions/delete",
            {
                "transaction_id": tx_id,
                "reason": "Удаление через UI"
            },
            token=self.token
        )
        self.assertEqual(status_del, 200)
        self.assertEqual(resp_del["status"], "success")


if __name__ == "__main__":
    unittest.main()
