import unittest
import json
import tempfile
import os
import shutil
import io
import sys
from pathlib import Path

sys.path.insert(0, r"C:\Users\User\Desktop\Таблицы")

from family_finances_os.db import EncryptedDatabaseStorage, init_database, get_connection
from family_finances_os.auth import AuthService
from family_finances_os.ledger import LedgerEngine
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

class TestGuardian1TransactionsCategories(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="ffos_g1_")
        self.db_path = Path(self.test_dir) / "test_g1.db"
        self.enc_path = Path(self.test_dir) / "test_g1.db.enc"

        init_database(self.db_path)
        self.conn = get_connection(self.db_path)
        self.auth = AuthService(conn_or_path=self.conn)
        self.owner = self.auth.create_owner("admin", "Глава семьи", "Family2026!")
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

    def _execute_http(self, method: str, path: str, body: dict = None) -> tuple[int, dict]:
        body_bytes = json.dumps(body).encode("utf-8") if body is not None else b""
        headers = [f"{method} {path} HTTP/1.1", "Host: 127.0.0.1", f"Authorization: Bearer {self.token}"]
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

    def test_01_categories_endpoints(self):
        # 1. GET /api/categories
        status, data = self._execute_http("GET", "/api/categories")
        self.assertEqual(status, 200)
        self.assertIn("tree", data)
        self.assertIn("flat", data)
        self.assertGreater(len(data["tree"]), 0)
        self.assertGreater(len(data["flat"]), 0)

        # 2. POST /api/categories/create
        create_payload = {
            "name": "Автотест Категория",
            "category_type": "EXPENSE",
            "icon": "🧪"
        }
        status, res = self._execute_http("POST", "/api/categories/create", create_payload)
        self.assertEqual(status, 200)
        self.assertEqual(res.get("status"), "success")
        self.assertIn("category", res)
        cat_id = res["category"].get("id")
        self.assertTrue(cat_id)

        # 3. POST /api/categories/update
        update_payload = {
            "category_id": cat_id,
            "name": "Автотест Категория (Обновлена)",
            "icon": "✨"
        }
        status, res = self._execute_http("POST", "/api/categories/update", update_payload)
        self.assertEqual(status, 200)
        self.assertEqual(res.get("status"), "success")

        # 4. POST /api/categories/archive
        status, res = self._execute_http("POST", "/api/categories/archive", {"category_id": cat_id})
        self.assertEqual(status, 200)
        self.assertEqual(res.get("status"), "success")

    def test_02_transaction_lifecycle_endpoints(self):
        # Setup asset and expense accounts
        asset_acc = self.ledger.get_account_by_code("1010")  # Карточный счет
        exp_acc = self.ledger.get_account_by_code("5010")    # Расходы на продукты

        # 1. POST /api/transaction/create
        tx_payload = {
            "tx_type": "EXPENSE",
            "account_id": asset_acc.id,
            "category_account_id": exp_acc.id,
            "category_id": "cat_food_super",
            "description": "Тестовые продукты ВкусВилл",
            "amount_rub": 850.50,
            "tx_date": "2026-11-10",
            "idempotency_key": "guardian1_key_001"
        }
        status, res = self._execute_http("POST", "/api/transaction/create", tx_payload)
        self.assertEqual(status, 200)
        self.assertEqual(res.get("status"), "success")
        tx_id = res.get("transaction_id")
        self.assertTrue(tx_id)

        # 2. GET /api/transactions
        status, res_tx = self._execute_http("GET", "/api/transactions?month=2026-11")
        self.assertEqual(status, 200)
        self.assertIn("transactions", res_tx)
        tx_list = res_tx["transactions"]
        found = [t for t in tx_list if t["id"] == tx_id]
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["category_id"], "cat_food_super")

        # 3. POST /api/transactions/update
        update_payload = {
            "transaction_id": tx_id,
            "tx_date": "2026-11-10",
            "amount_rub": 920.0,
            "description": "Тестовые продукты ВкусВилл (Чек скорректирован)",
            "account_id": asset_acc.id,
            "category_id": "cat_food_super",
            "tx_type": "EXPENSE"
        }
        status, res = self._execute_http("POST", "/api/transactions/update", update_payload)
        self.assertEqual(status, 200)
        self.assertEqual(res.get("status"), "success")

        # Verify update
        status, res_tx = self._execute_http("GET", "/api/transactions?month=2026-11")
        found = [t for t in res_tx["transactions"] if t["id"] == tx_id]
        self.assertEqual(len(found), 1)
        self.assertEqual(float(found[0]["amount_rub"]), 920.0)

        # 4. POST /api/transactions/delete
        delete_payload = {
            "transaction_id": tx_id,
            "reason": "Guardian verification cleanup"
        }
        status, res = self._execute_http("POST", "/api/transactions/delete", delete_payload)
        self.assertEqual(status, 200)
        self.assertEqual(res.get("status"), "success")

        # Verify voided
        status, res_tx = self._execute_http("GET", "/api/transactions?month=2026-11")
        active_found = [t for t in res_tx["transactions"] if t["id"] == tx_id and not t.get("is_voided")]
        self.assertEqual(len(active_found), 0)

    def test_03_quick_smart_input_endpoint(self):
        status, res = self._execute_http("POST", "/api/quick-tx/create", {"text": "450 кофе"})
        self.assertEqual(status, 200)
        self.assertEqual(res.get("status"), "success")
        self.assertEqual(float(res["parsed"]["amount_rub"]), 450.0)

    def test_04_html_and_css_contract(self):
        with open(r"C:\Users\User\Desktop\Таблицы\family_finances_os\web_server.py", "r", encoding="utf-8") as f:
            content = f.read()

        # Check required functions
        self.assertIn("function openNewTxModal", content)
        self.assertIn("function onTxTypeChange", content)
        self.assertIn("function setTxTypeSegment", content)
        self.assertIn("function toggleCategoryDropdown", content)
        self.assertIn("function filterCategoryDropdown", content)
        self.assertIn("function onSelectCategory", content)
        self.assertIn("async function submitSmartTx", content)
        self.assertIn("function openEditTxModal", content)
        self.assertIn("async function submitEditTx", content)
        self.assertIn("async function deleteTransaction", content)

        # Check .category-dropdown-list styling
        self.assertIn("max-height: 320px;", content)
        self.assertIn("overflow-y: auto !important;", content)
        self.assertIn("-webkit-overflow-scrolling: touch;", content)

if __name__ == "__main__":
    unittest.main()
