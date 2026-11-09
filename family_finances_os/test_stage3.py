"""
Family Finances OS - Stage 3 Comprehensive Verification Test Suite
Tests all requirements of Stage 3:
1. Category Tree Seeding (Default 26 categories, hierarchical parent-child structure)
2. Category CRUD (create, tree query, flat query, update, soft archive)
3. Transaction Postings linking with category_id & audit preservation
4. Recurring Obligations CRUD (creation, updating, day validation, soft archive)
5. Monthly Obligation Payment Lifecycle (mark paid, unmark paid, month isolation)
6. Safe-to-Spend reduction by upcoming unpaid monthly obligations
7. Deficit detection and alerting when obligations exceed liquid funds
8. Web API Category Endpoints (GET /api/categories, POST create, update, archive)
9. Web API Obligation Endpoints (GET /api/obligations, POST create, pay, unpay)
10. Web API Quick Transaction input with category selection and overview synchronization
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


class TestStage3CategoriesAndObligations(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="ffos_s3_")
        self.db_path = Path(self.test_dir) / "test_stage3.db"
        init_database(self.db_path)
        self.ledger = LedgerEngine(conn_or_path=self.db_path)
        self.ledger.seed_default_chart_of_accounts()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _seed_funds(self, account_id: str, amount_cents: int):
        salary_acc = self.ledger.get_account_by_code("4010")
        tx_id = generate_uuid()
        self.ledger.record_transaction(Transaction(
            id=tx_id,
            tx_date="2026-11-09",
            tx_type="INCOME",
            description="Пополнение счета",
            created_by_member_id=None,
            postings=[
                Posting(id=generate_uuid(), transaction_id=tx_id, account_id=account_id, amount_cents=amount_cents, posting_type="DEBIT"),
                Posting(id=generate_uuid(), transaction_id=tx_id, account_id=salary_acc.id, amount_cents=amount_cents, posting_type="CREDIT"),
            ]
        ))

    # 1. Category Tree Seeding
    def test_01_seed_default_categories(self):
        """Test default category tree seeding and idempotency."""
        created_ids = self.ledger.seed_default_categories()
        self.assertGreaterEqual(len(created_ids), 20, "Must seed at least 20 default categories")

        tree = self.ledger.get_category_tree("EXPENSE")
        self.assertGreater(len(tree), 0, "Expense category tree must have roots")

        # Find 'Питание и продукты'
        food_root = next((c for c in tree if "Питание" in c["name"] or "Продукты" in c["name"]), None)
        self.assertIsNotNone(food_root, "Food category root must exist")
        self.assertGreater(len(food_root["subcategories"]), 0, "Food category must have subcategories")

        # Idempotency: calling again should not fail and return empty list
        second_ids = self.ledger.seed_default_categories()
        self.assertEqual(len(second_ids), 0, "Idempotent call should return empty list without adding duplicates")
        flat = self.ledger.get_flat_categories()
        self.assertEqual(len(flat), len(created_ids))

    # 2. Category CRUD operations
    def test_02_category_crud(self):
        """Test creation, tree retrieval, flat retrieval, updating, and archiving of categories."""
        # Create root category
        cat_pets = self.ledger.create_category(
            name="Домашние питомцы",
            category_type="EXPENSE",
            icon="🐾",
            sort_order=50
        )
        self.assertIsNotNone(cat_pets.id)
        self.assertEqual(cat_pets.name, "Домашние питомцы")

        # Create subcategory
        cat_vet = self.ledger.create_category(
            name="Ветеринар и лекарства",
            category_type="EXPENSE",
            parent_id=cat_pets.id,
            icon="🏥",
            sort_order=51
        )
        self.assertEqual(cat_vet.parent_id, cat_pets.id)

        # Verify tree hierarchy
        tree = self.ledger.get_category_tree("EXPENSE")
        pets_in_tree = next((c for c in tree if c["id"] == cat_pets.id), None)
        self.assertIsNotNone(pets_in_tree)
        self.assertEqual(len(pets_in_tree["subcategories"]), 1)
        self.assertEqual(pets_in_tree["subcategories"][0]["id"], cat_vet.id)

        # Verify flat view
        flat = self.ledger.get_flat_categories("EXPENSE")
        vet_in_flat = next((c for c in flat if c["id"] == cat_vet.id), None)
        self.assertIsNotNone(vet_in_flat)
        self.assertEqual(vet_in_flat["parent_id"], cat_pets.id)
        self.assertEqual(vet_in_flat["parent_name"], "Домашние питомцы")

        # Update category
        ok = self.ledger.update_category(cat_pets.id, name="Питомцы и уход", icon="🐶")
        self.assertTrue(ok)
        tree_updated = self.ledger.get_category_tree("EXPENSE")
        pets_updated = next(c for c in tree_updated if c["id"] == cat_pets.id)
        self.assertEqual(pets_updated["name"], "Питомцы и уход")
        self.assertEqual(pets_updated["icon"], "🐶")

        # Archive category
        arch_ok = self.ledger.archive_category(cat_pets.id)
        self.assertTrue(arch_ok)
        tree_after = self.ledger.get_category_tree("EXPENSE")
        self.assertIsNone(next((c for c in tree_after if c["id"] == cat_pets.id), None))

    # 3. Transaction Postings linking with category_id
    def test_03_transaction_with_category(self):
        """Test recording transaction with category_id and audit trail preservation."""
        self.ledger.seed_default_categories()
        cat = self.ledger.create_category("Кофейни и перекусы", "EXPENSE", icon="☕")

        acc_card = self.ledger.get_account_by_code("1011")  # Карта Мужа
        acc_food = self.ledger.get_account_by_code("5010")  # Расходы: Продукты и питание

        tx_id = generate_uuid()
        postings = [
            Posting(id=generate_uuid(), transaction_id=tx_id, account_id=acc_food.id,
                    amount_cents=45000, posting_type="DEBIT", category_id=cat.id),
            Posting(id=generate_uuid(), transaction_id=tx_id, account_id=acc_card.id,
                    amount_cents=45000, posting_type="CREDIT")
        ]
        tx = Transaction(
            id=tx_id,
            tx_date="2026-11-09",
            tx_type="EXPENSE",
            description="Кофе в зернах",
            created_by_member_id=None,
            postings=postings
        )
        self.ledger.record_transaction(tx)

        # Verify posting has category_id
        conn = get_connection(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT category_id, amount_cents FROM postings WHERE transaction_id = ? AND posting_type = 'DEBIT';", (tx_id,))
        row = cursor.fetchone()
        conn.close()

        self.assertIsNotNone(row)
        self.assertEqual(row["category_id"], cat.id)
        self.assertEqual(row["amount_cents"], 45000)

    # 4. Recurring Obligations CRUD
    def test_04_obligations_crud(self):
        """Test creating, validating, updating, and archiving recurring fixed obligations."""
        self.ledger.seed_default_categories()
        cat = self.ledger.create_category("Аренда", "EXPENSE", icon="🏠")
        acc = self.ledger.get_account_by_code("1011")

        # 1. Create valid obligation
        obl = self.ledger.create_obligation(
            name="Аренда квартиры",
            amount_cents=rubles_to_cents(40000),
            due_day=20,
            category_id=cat.id,
            payment_account_id=acc.id,
            note="Оплата собственнику до 20 числа"
        )
        self.assertIsNotNone(obl.id)
        self.assertEqual(obl.name, "Аренда квартиры")
        self.assertEqual(obl.amount_cents, 4000000)
        self.assertEqual(obl.due_day, 20)

        # 2. Validation errors
        with self.assertRaises(ValueError):
            self.ledger.create_obligation("Ошибка суммы", amount_cents=0, due_day=5)
        with self.assertRaises(ValueError):
            self.ledger.create_obligation("Ошибка дня 0", amount_cents=1000, due_day=0)
        with self.assertRaises(ValueError):
            self.ledger.create_obligation("Ошибка дня 32", amount_cents=1000, due_day=32)

        # 3. Update obligation
        ok = self.ledger.update_obligation(obl.id, name="Аренда и паркинг", amount_cents=4500000, due_day=22)
        self.assertTrue(ok)

        obls = self.ledger.get_obligations()
        updated_obl = next(o for o in obls if o["id"] == obl.id)
        self.assertEqual(updated_obl["name"], "Аренда и паркинг")
        self.assertEqual(updated_obl["amount_cents"], 4500000)
        self.assertEqual(updated_obl["due_day"], 22)

        # 4. Archive obligation
        arch_ok = self.ledger.archive_obligation(obl.id)
        self.assertTrue(arch_ok)
        obls_after = self.ledger.get_obligations()
        self.assertIsNone(next((o for o in obls_after if o["id"] == obl.id), None))

    # 5. Monthly Obligation Payment Lifecycle
    def test_05_obligation_payment_lifecycle(self):
        """Test marking obligations paid, idempotency, unmarking, and monthly isolation."""
        obl = self.ledger.create_obligation(
            name="Домашний интернет",
            amount_cents=rubles_to_cents(800),
            due_day=5
        )

        month_curr = "2026-11"
        month_next = "2026-12"

        # Initially unpaid
        obls_curr = self.ledger.get_obligations(month_curr)
        self.assertFalse(obls_curr[0]["is_paid_this_month"])
        self.assertEqual(obls_curr[0]["remaining_cents"], 80000)

        # Mark paid for November
        paid_ok = self.ledger.mark_obligation_paid(obl.id, month_curr)
        self.assertTrue(paid_ok)

        obls_curr_after = self.ledger.get_obligations(month_curr)
        self.assertTrue(obls_curr_after[0]["is_paid_this_month"])
        self.assertEqual(obls_curr_after[0]["remaining_cents"], 0)
        self.assertEqual(obls_curr_after[0]["paid_amount_cents"], 80000)

        # Verify December is still unpaid (monthly isolation)
        obls_next = self.ledger.get_obligations(month_next)
        self.assertFalse(obls_next[0]["is_paid_this_month"])
        self.assertEqual(obls_next[0]["remaining_cents"], 80000)

        # Unmark payment in November
        unpay_ok = self.ledger.unmark_obligation_paid(obl.id, month_curr)
        self.assertTrue(unpay_ok)

        obls_curr_unpaid = self.ledger.get_obligations(month_curr)
        self.assertFalse(obls_curr_unpaid[0]["is_paid_this_month"])
        self.assertEqual(obls_curr_unpaid[0]["remaining_cents"], 80000)

    # 6. Safe-to-Spend reduction by upcoming unpaid monthly obligations
    def test_06_safe_to_spend_accounting_for_obligations(self):
        """
        Core Financial Rule Verification:
        Safe-to-Spend MUST strictly deduct upcoming unpaid monthly obligations.
        Given:
          - Common Liquid Assets = 100,000 ₽
          - Credit Debt = 0 ₽
          - Obligation 1 (Rent) = 35,000 ₽ (Unpaid)
          - Obligation 2 (Internet) = 1,000 ₽ (Unpaid)
        Expected Safe-to-Spend = 100,000 - 36,000 = 64,000 ₽.
        When Obligation 1 is marked paid:
        Expected Safe-to-Spend = 100,000 - 1,000 = 99,000 ₽.
        """
        acc_card = self.ledger.get_account_by_code("1011")
        # Give account 100,000 ₽ balance
        self._seed_funds(acc_card.id, rubles_to_cents(100000))

        obl_rent = self.ledger.create_obligation("Аренда", rubles_to_cents(35000), 20)
        obl_net = self.ledger.create_obligation("Интернет", rubles_to_cents(1000), 1)

        overview = self.ledger.get_financial_overview()
        self.assertEqual(overview["common_liquid_assets_cents"], 10000000)  # 100,000 ₽
        self.assertEqual(overview["unpaid_obligations_cents"], 3600000)     # 36,000 ₽
        self.assertEqual(overview["common_safe_to_spend_cents"], 6400000)   # 64,000 ₽
        self.assertFalse(overview["is_deficit"])

        # Mark rent paid
        self.ledger.mark_obligation_paid(obl_rent.id)

        overview2 = self.ledger.get_financial_overview()
        self.assertEqual(overview2["unpaid_obligations_cents"], 100000)     # 1,000 ₽
        self.assertEqual(overview2["paid_obligations_cents"], 3500000)      # 35,000 ₽
        self.assertEqual(overview2["common_safe_to_spend_cents"], 9900000)  # 99,000 ₽

    # 7. Deficit detection and alerting when obligations exceed liquid funds
    def test_07_safe_to_spend_deficit_when_obligations_exceed_liquidity(self):
        """
        Verify deficit calculation when unpaid obligations exceed liquid assets:
        Given: Liquid = 20,000 ₽, Obligations = 50,000 ₽
        Expected: Net Safe-to-Spend = -30,000 ₽, is_deficit = True, deficit = 30,000 ₽, safe_to_spend = 0 ₽.
        """
        acc_card = self.ledger.get_account_by_code("1011")
        self._seed_funds(acc_card.id, rubles_to_cents(20000))

        self.ledger.create_obligation("Ипотека", rubles_to_cents(50000), 10)

        overview = self.ledger.get_financial_overview()
        self.assertEqual(overview["common_liquid_assets_cents"], 2000000)
        self.assertEqual(overview["unpaid_obligations_cents"], 5000000)
        self.assertEqual(overview["net_safe_to_spend_cents"], -3000000)
        self.assertEqual(overview["common_safe_to_spend_cents"], 0)
        self.assertTrue(overview["is_deficit"])
        self.assertEqual(overview["deficit_cents"], 3000000)
        self.assertEqual(overview["deficit_rub"], "30000.00")

    # 8. Web API Category Endpoints
    def test_08_web_api_categories_endpoints(self):
        """Verify GET /api/categories and POST /api/categories/create, update, archive."""
        user_info = {"user_id": "u_test", "username": "admin", "role": "OWNER"}
        valid_token = GLOBAL_SESSION_MANAGER.create_session(user_info)

        # 1. GET /api/categories
        req_get = f"GET /api/categories HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {valid_token}\r\n\r\n".encode()
        sock_get = MockSocket(req_get)
        FamilyFinancesHandler(sock_get, ("127.0.0.1", 12345), None)
        self.assertIn(b"200 OK", bytes(sock_get.output))

        # 2. POST /api/categories/create
        cat_payload = json.dumps({"name": "Хобби и спорт", "category_type": "EXPENSE", "icon": "⚽", "sort_order": 70}).encode()
        req_create = f"POST /api/categories/create HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {valid_token}\r\nContent-Length: {len(cat_payload)}\r\n\r\n".encode() + cat_payload
        sock_create = MockSocket(req_create)
        FamilyFinancesHandler(sock_create, ("127.0.0.1", 12345), None)
        self.assertIn(b"200 OK", bytes(sock_create.output))
        resp_data = json.loads(bytes(sock_create.output).split(b"\r\n\r\n", 1)[1])
        cat_id = resp_data["category"]["id"]

        # 3. POST /api/categories/update
        update_payload = json.dumps({"category_id": cat_id, "name": "Спортзал и инвентарь", "icon": "🏋️"}).encode()
        req_up = f"POST /api/categories/update HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {valid_token}\r\nContent-Length: {len(update_payload)}\r\n\r\n".encode() + update_payload
        sock_up = MockSocket(req_up)
        FamilyFinancesHandler(sock_up, ("127.0.0.1", 12345), None)
        self.assertIn(b"200 OK", bytes(sock_up.output))

        # 4. POST /api/categories/archive
        arch_payload = json.dumps({"category_id": cat_id}).encode()
        req_arch = f"POST /api/categories/archive HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {valid_token}\r\nContent-Length: {len(arch_payload)}\r\n\r\n".encode() + arch_payload
        sock_arch = MockSocket(req_arch)
        FamilyFinancesHandler(sock_arch, ("127.0.0.1", 12345), None)
        self.assertIn(b"200 OK", bytes(sock_arch.output))

    # 9. Web API Obligation Endpoints
    def test_09_web_api_obligations_endpoints(self):
        """Verify GET /api/obligations, POST create, pay, unpay."""
        user_info = {"user_id": "u_test", "username": "admin", "role": "OWNER"}
        valid_token = GLOBAL_SESSION_MANAGER.create_session(user_info)

        # 1. POST /api/obligations/create
        obl_payload = json.dumps({
            "name": "Мобильная связь",
            "amount_rub": "650",
            "due_day": 12,
            "note": "Тариф Семья"
        }).encode()
        req_create = f"POST /api/obligations/create HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {valid_token}\r\nContent-Length: {len(obl_payload)}\r\n\r\n".encode() + obl_payload
        sock_create = MockSocket(req_create)
        FamilyFinancesHandler(sock_create, ("127.0.0.1", 12345), None)
        self.assertIn(b"200 OK", bytes(sock_create.output))
        resp_data = json.loads(bytes(sock_create.output).split(b"\r\n\r\n", 1)[1])
        obl_id = resp_data["obligation"]["id"]

        # 2. GET /api/obligations
        req_get = f"GET /api/obligations HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {valid_token}\r\n\r\n".encode()
        sock_get = MockSocket(req_get)
        FamilyFinancesHandler(sock_get, ("127.0.0.1", 12345), None)
        self.assertIn(b"200 OK", bytes(sock_get.output))

        # 3. POST /api/obligations/pay
        pay_payload = json.dumps({"obligation_id": obl_id}).encode()
        req_pay = f"POST /api/obligations/pay HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {valid_token}\r\nContent-Length: {len(pay_payload)}\r\n\r\n".encode() + pay_payload
        sock_pay = MockSocket(req_pay)
        FamilyFinancesHandler(sock_pay, ("127.0.0.1", 12345), None)
        self.assertIn(b"200 OK", bytes(sock_pay.output))

        # 4. POST /api/obligations/unpay
        unpay_payload = json.dumps({"obligation_id": obl_id}).encode()
        req_unpay = f"POST /api/obligations/unpay HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {valid_token}\r\nContent-Length: {len(unpay_payload)}\r\n\r\n".encode() + unpay_payload
        sock_unpay = MockSocket(req_unpay)
        FamilyFinancesHandler(sock_unpay, ("127.0.0.1", 12345), None)
        self.assertIn(b"200 OK", bytes(sock_unpay.output))

    # 10. Web API Quick Transaction input with category
    def test_10_web_api_transaction_with_category(self):
        """Verify POST /api/transaction/create with category_id and GET /api/transactions."""
        user_info = {"user_id": "u_test", "username": "admin", "role": "OWNER"}
        valid_token = GLOBAL_SESSION_MANAGER.create_session(user_info)

        ledger = LedgerEngine()
        ledger.seed_default_chart_of_accounts()
        ledger.seed_default_categories()
        cat = ledger.create_category("Аптека и здоровье", "EXPENSE", icon="💊")
        acc = ledger.get_account_by_code("1011")
        cat_acc = ledger.get_account_by_code("5010")

        tx_payload = json.dumps({
            "tx_type": "EXPENSE",
            "account_id": acc.id,
            "category_account_id": cat_acc.id,
            "category_id": cat.id,
            "amount_rub": "1250",
            "description": "Витамины и аспирин"
        }).encode()

        req_tx = f"POST /api/transaction/create HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {valid_token}\r\nContent-Length: {len(tx_payload)}\r\n\r\n".encode() + tx_payload
        sock_tx = MockSocket(req_tx)
        FamilyFinancesHandler(sock_tx, ("127.0.0.1", 12345), None)
        self.assertIn(b"200 OK", bytes(sock_tx.output))

        # Verify GET /api/transactions contains category_name and icon
        req_list = f"GET /api/transactions HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {valid_token}\r\n\r\n".encode()
        sock_list = MockSocket(req_list)
        FamilyFinancesHandler(sock_list, ("127.0.0.1", 12345), None)
        self.assertIn(b"200 OK", bytes(sock_list.output))
        resp_list = json.loads(bytes(sock_list.output).split(b"\r\n\r\n", 1)[1])
        tx_item = next((t for t in resp_list if t["description"] == "Витамины и аспирин"), None)
        self.assertIsNotNone(tx_item)
        self.assertEqual(tx_item["category_name"], "Аптека и здоровье")
        self.assertEqual(tx_item["category_icon"], "💊")


if __name__ == "__main__":
    unittest.main(verbosity=2)
