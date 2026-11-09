"""
Stage 14 Test Suite: Debts Button, Category Tree & Repayment Categorization Integrity
Verifies:
1. Debt category tree in seed_default_categories (root cat_debts + subcategories + cat_borrow_income).
2. Idempotency and automatic backfill for existing databases.
3. Proper category assignment in create_debt (obligations & initial postings).
4. Category assignment in record_debt_repayment (default by subtype or explicit category_id).
5. Frontend HTML integrity:
   - Exactly ONE #tab-debts container (no duplicate DOM elements).
   - "➕ Добавить долг или карту" button present in #tab-debts.
   - "➕ Добавить долг" button present in #tab-overview quick actions.
   - Category selector #payDebtCategory present in #modalPayDebt.
   - Category label #newDebtCategoryLabel present in #modalNewDebt.
"""

import unittest
import os
import shutil
import tempfile
import json
from pathlib import Path
from family_finances_os.db import init_database, get_connection
from family_finances_os.ledger import LedgerEngine, DEBT_CATEGORY_MAP
from family_finances_os.models import Account, Transaction, Posting
from family_finances_os.auth import AuthService

class TestStage14DebtButtonAndCategories(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_path = Path(self.test_dir) / "test_ffos.db"
        init_database(self.db_path)
        self.conn = get_connection(self.db_path)
        self.ledger = LedgerEngine(conn_or_path=self.conn)
        self.ledger.seed_default_chart_of_accounts()
        self.auth = AuthService(conn_or_path=self.conn)
        self.user = self.auth.create_owner(username="testuser", display_name="Tester", password="correct_password")

    def tearDown(self):
        if self.conn:
            self.conn.close()
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_01_seed_debt_categories_present(self):
        """Test default seeding creates the full debt categories hierarchy."""
        created = self.ledger.seed_default_categories()
        self.assertIn("cat_debts", created)
        self.assertIn("cat_debts_credit_card", created)
        self.assertIn("cat_debts_consumer", created)
        self.assertIn("cat_debts_mortgage", created)
        self.assertIn("cat_debts_auto", created)
        self.assertIn("cat_debts_bnpl", created)
        self.assertIn("cat_debts_personal", created)
        self.assertIn("cat_debts_interest", created)
        self.assertIn("cat_borrow_income", created)

        # Check tree
        tree = self.ledger.get_category_tree("EXPENSE")
        debt_node = next((c for c in tree if c["id"] == "cat_debts"), None)
        self.assertIsNotNone(debt_node, "Root category cat_debts must exist in tree")
        sub_ids = [s["id"] for s in debt_node["subcategories"]]
        self.assertIn("cat_debts_credit_card", sub_ids)
        self.assertIn("cat_debts_mortgage", sub_ids)

        # Idempotency: second call returns empty list
        second = self.ledger.seed_default_categories()
        self.assertEqual(len(second), 0, "Idempotent call should return empty list without duplicates")

    def test_02_migration_backfill_existing_database(self):
        """Test that calling seed_default_categories on a DB with only legacy categories adds debt categories."""
        # Clean categories table
        cur = self.conn.cursor()
        cur.execute("DELETE FROM categories;")
        # Insert only legacy food category
        cur.execute("INSERT INTO categories (id, name, category_type, sort_order, is_active) VALUES ('cat_food', 'Food', 'EXPENSE', 10, 1);")
        self.conn.commit()

        # Seed categories
        new_ids = self.ledger.seed_default_categories()
        self.assertNotIn("cat_food", new_ids, "Existing category should not be re-inserted")
        self.assertIn("cat_debts", new_ids, "cat_debts must be backfilled")
        self.assertIn("cat_debts_credit_card", new_ids)

    def test_03_create_debt_links_obligation_category(self):
        """Test that creating a debt with recurring obligation assigns the appropriate debt category."""
        self.ledger.seed_default_categories()

        res = self.ledger.create_debt(
            name="Кредитная СберКарта ТП-1001",
            subtype="CREDIT_CARD",
            credit_limit_cents=16500000,
            initial_debt_cents=5000000,
            monthly_payment_cents=300000,
            due_day=15
        )
        self.assertEqual(res["status"], "success")
        ob_id = res["obligation_id"]
        self.assertIsNotNone(ob_id)

        cur = self.conn.cursor()
        cur.execute("SELECT category_id FROM obligations WHERE id = ?;", (ob_id,))
        row = cur.fetchone()
        self.assertEqual(row["category_id"], "cat_debts_credit_card", "Obligation must be linked to cat_debts_credit_card")

    def test_04_record_debt_repayment_assigns_categories(self):
        """Test that debt repayment automatically assigns the category to postings."""
        self.ledger.seed_default_categories()

        # Create cash asset
        asset_acc = self.ledger.create_account(
            name="Сбербанк Дебетовая",
            account_type="ASSET",
            subtype="CHECKING",
            ownership_scope="COMMON",
            initial_balance_cents=20000000
        )

        # Create credit card liability
        card_res = self.ledger.create_debt(
            name="Тинькофф Платинум",
            subtype="CREDIT_CARD",
            credit_limit_cents=10000000,
            initial_debt_cents=4000000
        )
        liab_acc_id = card_res["account_id"]

        # 1. Repay with default category
        tx_id1 = self.ledger.record_debt_repayment(
            source_account_id=asset_acc.id,
            liability_account_id=liab_acc_id,
            amount_cents=1000000
        )
        cur = self.conn.cursor()
        cur.execute("SELECT category_id FROM postings WHERE transaction_id = ?;", (tx_id1,))
        postings = cur.fetchall()
        self.assertEqual(len(postings), 2)
        for p in postings:
            self.assertEqual(p["category_id"], "cat_debts_credit_card")

        # 2. Repay with explicit category (e.g. paying bank interest/penalty)
        tx_id2 = self.ledger.record_debt_repayment(
            source_account_id=asset_acc.id,
            liability_account_id=liab_acc_id,
            amount_cents=50000,
            category_id="cat_debts_interest",
            description="Оплата процентов банку"
        )
        cur.execute("SELECT category_id FROM postings WHERE transaction_id = ?;", (tx_id2,))
        postings2 = cur.fetchall()
        for p in postings2:
            self.assertEqual(p["category_id"], "cat_debts_interest")

    def test_05_web_server_html_and_dom_integrity(self):
        """Test rendered HTML: exactly one #tab-debts container and presence of Add Debt buttons."""
        import re
        web_server_path = os.path.join(os.path.dirname(__file__), "web_server.py")
        with open(web_server_path, "r", encoding="utf-8") as f:
            html = f.read()

        # Check #tab-debts container count in HTML
        matches = re.findall(r'<div\s+id=[\'"]tab-debts[\'"]', html)
        self.assertEqual(len(matches), 1, f"There must be exactly ONE #tab-debts container in web_server.py, found {len(matches)}")

        # Check Add Debt button in #tab-debts
        self.assertIn("openNewDebtModal()", html, "openNewDebtModal() trigger must exist")
        self.assertIn("Добавить долг или карту", html, "'Добавить долг или карту' button must exist in #tab-debts")

        # Check Add Debt button in #tab-overview
        self.assertIn("➕ Добавить долг", html, "'➕ Добавить долг' button must exist in overview quick actions")

        # Check category dropdown in modalPayDebt
        self.assertIn('id="payDebtCategory"', html, "#payDebtCategory select must exist in #modalPayDebt")

        # Check category label in modalNewDebt
        self.assertIn('id="newDebtCategoryLabel"', html, "#newDebtCategoryLabel must exist in #modalNewDebt")

if __name__ == "__main__":
    unittest.main()
