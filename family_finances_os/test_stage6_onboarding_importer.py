"""
Family Finances OS - Stage 6 Comprehensive Verification Test Suite
Verifies:
1. Double-entry opening balance setup for ASSET accounts (Dr Account, Cr 3010 Equity)
2. Double-entry opening debt setup for LIABILITY accounts (Dr 3010 Equity, Cr Credit Card)
3. Atomic batch onboarding setup (Initial balances + Obligations + Safe-to-Spend initialization)
4. Bank statement CSV parsing with automatic comma/dot cleaning and keyword categorization
5. Statement commit into ledger with double-entry balancing and idempotent deduplication
6. Web API endpoints (/api/onboarding/setup, /api/accounts/set-initial-balance, /api/import/preview, /api/import/confirm)
"""
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from family_finances_os.db import EncryptedDatabaseStorage, get_connection, init_database
from family_finances_os.ledger import LedgerEngine
from family_finances_os.importer import StatementImporter, clean_amount_str, guess_category
from family_finances_os.models import rubles_to_cents, cents_to_rubles, generate_uuid
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


class TestStage6OnboardingImporter(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="ffos_s6_")
        self.db_path = Path(self.test_dir) / "test_s6.db"
        init_database(self.db_path)
        self.conn = get_connection(self.db_path)
        self.ledger = LedgerEngine(conn_or_path=self.conn)
        self.ledger.seed_default_chart_of_accounts()
        self.ledger.seed_default_categories()
        self.importer = StatementImporter(ledger=self.ledger)

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
        # Point handler storage to a temporary memory storage with active conn
        original_storage = FamilyFinancesHandler.storage
        test_storage = EncryptedDatabaseStorage(enc_path=Path(self.test_dir) / "mock.db.enc")
        test_storage._active_conn = self.conn
        test_storage._dek = bytearray(b"\x01" * 32)
        FamilyFinancesHandler.storage = test_storage
        try:
            FamilyFinancesHandler(sock, ("127.0.0.1", 12345), None)
        finally:
            FamilyFinancesHandler.storage = original_storage

        raw_output = bytes(sock.output)
        status_line = raw_output.split(b"\r\n", 1)[0].decode("utf-8")
        status_code = int(status_line.split(" ")[1])
        parts = raw_output.split(b"\r\n\r\n", 1)
        resp_json = json.loads(parts[1].decode("utf-8")) if len(parts) > 1 and parts[1].strip() else {}
        return status_code, resp_json

    # 1. Opening balance setup for ASSET
    def test_01_set_initial_balance_asset(self):
        """Setting initial balance on asset card creates double-entry Debit Account, Credit 3010 Equity."""
        main_card = self.ledger.get_account_by_code("1010")
        self.ledger.set_initial_balance(main_card.id, rubles_to_cents(50000))

        ov = self.ledger.get_financial_overview()
        self.assertEqual(ov["common_liquid_assets_rub"], "50000.00")
        self.assertEqual(ov["common_safe_to_spend_rub"], "50000.00")
        self.assertEqual(ov["family_net_worth_rub"], "50000.00")

        # Verify transaction in DB
        cur = self.conn.cursor()
        cur.execute("SELECT tx_type, description FROM transactions WHERE idempotency_key = ?;", (f"init_bal_{main_card.id}",))
        tx = cur.fetchone()
        self.assertIsNotNone(tx)
        self.assertEqual(tx["tx_type"], "ADJUSTMENT")

    # 2. Opening debt setup for LIABILITY
    def test_02_set_initial_balance_liability(self):
        """Setting existing debt on credit card debits 3010 Equity and credits liability, reducing Safe-to-Spend."""
        main_card = self.ledger.get_account_by_code("1010")
        cred_card = self.ledger.get_account_by_code("2020")

        self.ledger.set_initial_balance(main_card.id, rubles_to_cents(50000))
        self.ledger.set_initial_balance(cred_card.id, rubles_to_cents(15000))
        self.ledger.update_account(cred_card.id, name=None, credit_limit_cents=rubles_to_cents(100000))

        ov = self.ledger.get_financial_overview()
        self.assertEqual(ov["common_liquid_assets_rub"], "50000.00")
        self.assertEqual(ov["credit_cards"]["total_debt_rub"], "15000.00")
        # Safe-to-Spend = 50,000 - 15,000 = 35,000 ₽
        self.assertEqual(ov["common_safe_to_spend_rub"], "35000.00")
        self.assertEqual(ov["family_net_worth_rub"], "35000.00")

    # 3. Batch onboarding setup
    def test_03_batch_onboarding_setup(self):
        """Batch setup initializes multiple balances and obligations atomically."""
        main_acc = self.ledger.get_account_by_code("1010")
        wife_acc = self.ledger.get_account_by_code("1020")
        cred_acc = self.ledger.get_account_by_code("2020")
        cat_food = next(c for c in self.ledger.get_flat_categories() if c["type"] == "EXPENSE")

        balances = [
            {"account_id": main_acc.id, "balance_cents": rubles_to_cents(40000)},
            {"account_id": wife_acc.id, "balance_cents": rubles_to_cents(30000)},
            {"account_id": cred_acc.id, "balance_cents": rubles_to_cents(10000), "credit_limit_cents": rubles_to_cents(150000)}
        ]
        obligations = [
            {"name": "Аренда квартиры", "amount_cents": rubles_to_cents(25000), "due_day": 20, "category_id": cat_food["id"]}
        ]

        res = self.ledger.batch_onboarding_setup(balances=balances, obligations=obligations)
        self.assertEqual(res["status"], "success")

        ov = res["overview"]
        # Liquid = 40,000 + 30,000 = 70,000 ₽
        self.assertEqual(ov["common_liquid_assets_rub"], "70000.00")
        # Credit Debt = 10,000 ₽
        self.assertEqual(ov["credit_cards"]["total_debt_rub"], "10000.00")
        # Obligations = 25,000 ₽
        self.assertEqual(ov["unpaid_obligations_rub"], "25000.00")
        # Safe-to-Spend = 70,000 - 10,000 - 25,000 = 35,000 ₽
        self.assertEqual(ov["common_safe_to_spend_rub"], "35000.00")

    # 4. Bank statement CSV parsing and keyword categorization
    def test_04_statement_importer_csv_parsing(self):
        """CSV parser handles various bank formats and keywords (Перекресток, Аптека, Зарплата)."""
        csv_sample = """Дата;Описание;Сумма
09.11.2026;Супермаркет Перекресток 145;-1 450,50 ₽
08.11.2026;Аптека Горздрав №12;-850.00
07.11.2026;АЗС Лукойл 77;-2500,00
05.11.2026;Зарплата за октябрь;+85 000,00
"""
        items = self.importer.parse_csv(csv_sample)
        self.assertEqual(len(items), 4)

        # 1. Groceries
        self.assertEqual(items[0]["amount_cents"], 145050)
        self.assertEqual(items[0]["direction"], "EXPENSE")
        self.assertIn("Продукт", items[0]["category_name"])

        # 2. Pharmacy
        self.assertEqual(items[1]["amount_cents"], 85000)
        self.assertTrue(any(k in items[1]["category_name"] for k in ["Аптек", "Здоровье"]))

        # 3. Gas / Auto
        self.assertEqual(items[2]["amount_cents"], 250000)
        self.assertTrue(any(k in items[2]["category_name"] for k in ["Топлив", "АЗС", "Транспорт"]))

        # 4. Salary
        self.assertEqual(items[3]["amount_cents"], 8500000)
        self.assertEqual(items[3]["direction"], "INCOME")
        self.assertIn("Зарплат", items[3]["category_name"])

    # 5. Statement commit and idempotent deduplication
    def test_05_statement_importer_commit_and_deduplication(self):
        """Committing imported items applies double entry; re-importing skips duplicates."""
        main_acc = self.ledger.get_account_by_code("1010")
        # Seed initial 10,000 ₽
        self.ledger.set_initial_balance(main_acc.id, rubles_to_cents(10000))

        csv_data = """Дата,Описание,Сумма
2026-11-09,Кафе Вкусно и Точка,-650.00
2026-11-09,Такси Яндекс Go,-450.00
"""
        items = self.importer.parse_csv(csv_data)
        self.assertEqual(len(items), 2)

        # First commit
        res1 = self.importer.commit_imported_items(items, account_id=main_acc.id)
        self.assertEqual(res1["imported_count"], 2)
        self.assertEqual(res1["skipped_count"], 0)

        # Balance check: 10,000 - 650 - 450 = 8,900 ₽
        ov = self.ledger.get_financial_overview()
        self.assertEqual(ov["common_liquid_assets_rub"], "8900.00")

        # Second commit of the same items (must be skipped cleanly via idempotency keys)
        res2 = self.importer.commit_imported_items(items, account_id=main_acc.id)
        self.assertEqual(res2["imported_count"], 0)
        self.assertEqual(res2["skipped_count"], 2)

        # Balance remains unchanged: 8,900 ₽
        ov2 = self.ledger.get_financial_overview()
        self.assertEqual(ov2["common_liquid_assets_rub"], "8900.00")

    # 6. HTTP API Endpoints
    def test_06_http_api_endpoints(self):
        """Verify /api/onboarding/setup, /api/accounts/set-initial-balance, /api/import/preview, /api/import/confirm."""
        token = GLOBAL_SESSION_MANAGER.create_session({"user_id": "u_test", "username": "admin", "role": "OWNER"})
        main_acc = self.ledger.get_account_by_code("1010")

        # 1. /api/accounts/set-initial-balance
        code, resp = self._execute_http("POST", "/api/accounts/set-initial-balance", {
            "account_id": main_acc.id, "balance_rub": "15000"
        }, token=token)
        self.assertEqual(code, 200)
        self.assertEqual(resp["status"], "success")

        # 2. /api/onboarding/setup
        code_ob, resp_ob = self._execute_http("POST", "/api/onboarding/setup", {
            "balances": [{"account_id": main_acc.id, "balance_cents": rubles_to_cents(25000)}],
            "obligations": []
        }, token=token)
        self.assertEqual(code_ob, 200)
        self.assertEqual(resp_ob["status"], "success")

        # 3. /api/import/preview
        raw_csv = "Дата;Описание;Сумма\n2026-11-09;Супермаркет Магнит;-500.00"
        code_prev, resp_prev = self._execute_http("POST", "/api/import/preview", {
            "csv_text": raw_csv
        }, token=token)
        self.assertEqual(code_prev, 200)
        self.assertEqual(resp_prev["count"], 1)

        # 4. /api/import/confirm
        code_conf, resp_conf = self._execute_http("POST", "/api/import/confirm", {
            "account_id": main_acc.id,
            "items": resp_prev["items"]
        }, token=token)
        self.assertEqual(code_conf, 200)
        self.assertEqual(resp_conf["imported_count"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
