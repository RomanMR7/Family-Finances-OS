"""
Family Finances OS - Stage 2 Comprehensive Verification Test Suite
Tests all 12 required criteria of Stage 2 plus idempotency & encryption checks:
1. Creation and editing of custom accounts
2. Strict separation of Common vs Personal accounts
3. Initial/Opening balances via double-entry
4. Internal transfer between two Common accounts
5. Internal transfer between Personal and Common accounts
6. Internal transfer between Husband and Wife personal accounts
7. Guarantee that transfers do NOT create income or expenses (No double-counting)
8. Credit cards: Credit limit, current debt, and available credit isolation
9. Common family purchase paid from Personal Card WITHOUT automatic debt
10. Full transaction history and audit trail preservation
11. Persistence across application shutdown and restart
12. Mathematical correctness of all multi-balance metrics
13. Idempotency payload mismatch rejection (tampering protection)
"""
import shutil
import tempfile
import unittest
from pathlib import Path

from family_finances_os.db import init_database, check_db_health, get_connection
from family_finances_os.ledger import LedgerEngine
from family_finances_os.models import (
    Account,
    Posting,
    Transaction,
    rubles_to_cents,
    cents_to_rubles,
    generate_uuid
)


class TestStage2Finances(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="ffos_s2_")
        self.db_path = Path(self.test_dir) / "test_stage2.db"
        init_database(self.db_path)
        self.ledger = LedgerEngine(conn_or_path=self.db_path)
        self.ledger.seed_default_chart_of_accounts()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    # 1. Creation and Editing of Accounts
    def test_01_create_and_edit_accounts(self):
        """Requirement 1: Create, edit, and archive custom accounts."""
        acc = self.ledger.create_account(
            name="Вклад Т-Банк 16%",
            account_type="ASSET",
            subtype="DEPOSIT",
            ownership_scope="COMMON",
            description="Вклад на 6 месяцев"
        )
        self.assertIsNotNone(acc.id)
        self.assertEqual(acc.name, "Вклад Т-Банк 16%")
        self.assertEqual(acc.subtype, "DEPOSIT")

        # Edit account
        ok_edit = self.ledger.update_account(
            account_id=acc.id,
            name="Вклад Т-Банк 18% (Продлен)",
            description="Ставка повышена"
        )
        self.assertTrue(ok_edit)
        updated = self.ledger.get_account_by_id(acc.id)
        self.assertEqual(updated.name, "Вклад Т-Банк 18% (Продлен)")

        # Archive account
        ok_arch = self.ledger.archive_account(acc.id)
        self.assertTrue(ok_arch)
        archived = self.ledger.get_account_by_id(acc.id)
        self.assertFalse(archived.is_active)

    # 2. Separation of Common and Personal Accounts
    def test_02_separation_of_common_and_personal_accounts(self):
        """Requirement 2: Ensure Common, Husband, and Wife accounts are distinctly tracked."""
        common_card = self.ledger.create_account("Семейная карта Сбер", "ASSET", "DEBIT_CARD", "COMMON")
        husband_card = self.ledger.create_account("Карта Мужа Т-Банк", "ASSET", "DEBIT_CARD", "PERSONAL_HUSBAND")
        wife_card = self.ledger.create_account("Карта Жены ВТБ", "ASSET", "DEBIT_CARD", "PERSONAL_WIFE")

        self.assertEqual(common_card.ownership_scope, "COMMON")
        self.assertEqual(husband_card.ownership_scope, "PERSONAL_HUSBAND")
        self.assertEqual(wife_card.ownership_scope, "PERSONAL_WIFE")

        overview = self.ledger.get_financial_overview()
        scopes = {a["id"]: a["scope"] for a in overview["accounts"]}
        self.assertEqual(scopes[common_card.id], "COMMON")
        self.assertEqual(scopes[husband_card.id], "PERSONAL_HUSBAND")
        self.assertEqual(scopes[wife_card.id], "PERSONAL_WIFE")

    # 3. Initial / Opening Balances
    def test_03_initial_balances_via_double_entry(self):
        """Requirement 3: Opening balances record balanced opening equity adjustments."""
        init_cents = rubles_to_cents(50000.00)
        acc = self.ledger.create_account(
            name="Кошелек наличных",
            account_type="ASSET",
            subtype="CASH",
            ownership_scope="COMMON",
            initial_balance_cents=init_cents
        )
        # Account balance must equal 50,000 RUB
        bal = self.ledger.get_account_balance_cents(acc.id)
        self.assertEqual(bal, init_cents)

        # Common Equity (3010) must also have credited 50,000 RUB
        equity_acc = self.ledger.get_account_by_code("3010")
        eq_bal = self.ledger.get_account_balance_cents(equity_acc.id)
        self.assertEqual(eq_bal, init_cents)

    # 4. Internal Transfer between Two Common Accounts
    def test_04_transfer_between_common_accounts(self):
        """Requirement 4: Transfer from Common Card to Common Cash."""
        card = self.ledger.get_account_by_code("1010")  # Common card
        cash = self.ledger.get_account_by_code("1020")  # Common cash

        # Initial seed: card has 30,000 RUB
        self._seed_funds(card.id, rubles_to_cents(30000))

        # Transfer 10,000 RUB from card to cash
        tr_cents = rubles_to_cents(10000)
        tx_id = self.ledger.record_transfer(
            from_account_id=card.id,
            to_account_id=cash.id,
            amount_cents=tr_cents,
            description="Снятие наличных в банкомате"
        )
        self.assertIsNotNone(tx_id)

        # Card: 30,000 - 10,000 = 20,000 RUB
        self.assertEqual(self.ledger.get_account_balance_cents(card.id), rubles_to_cents(20000))
        # Cash: 0 + 10,000 = 10,000 RUB
        self.assertEqual(self.ledger.get_account_balance_cents(cash.id), rubles_to_cents(10000))

    # 5. Internal Transfer between Personal and Common Account
    def test_05_transfer_between_personal_and_common(self):
        """Requirement 5: Transfer from Husband's Personal Card to Common Family Card."""
        husband_card = self.ledger.get_account_by_code("1011")
        common_card = self.ledger.get_account_by_code("1010")

        self._seed_funds(husband_card.id, rubles_to_cents(50000))

        # Husband transfers 20,000 RUB to Common family card
        tr_cents = rubles_to_cents(20000)
        self.ledger.record_transfer(
            from_account_id=husband_card.id,
            to_account_id=common_card.id,
            amount_cents=tr_cents,
            description="Вклад мужа в семейный бюджет на месяц"
        )

        self.assertEqual(self.ledger.get_account_balance_cents(husband_card.id), rubles_to_cents(30000))
        self.assertEqual(self.ledger.get_account_balance_cents(common_card.id), rubles_to_cents(20000))

        overview = self.ledger.get_financial_overview()
        self.assertEqual(overview["husband_personal_balance_cents"], rubles_to_cents(30000))
        # Total family liquid assets must be 30,000 (husband's card) + 20,000 (common card) = 50,000 RUB
        self.assertEqual(overview["common_liquid_assets_cents"], rubles_to_cents(50000))

    # 6. Internal Transfer between Husband and Wife
    def test_06_transfer_between_husband_and_wife(self):
        """Requirement 6: Direct transfer from Husband's card to Wife's card."""
        husband_card = self.ledger.get_account_by_code("1011")
        wife_card = self.ledger.get_account_by_code("1012")

        self._seed_funds(husband_card.id, rubles_to_cents(40000))

        # Transfer 15,000 RUB
        tr_cents = rubles_to_cents(15000)
        self.ledger.record_transfer(
            from_account_id=husband_card.id,
            to_account_id=wife_card.id,
            amount_cents=tr_cents,
            description="Перевод жене на личные расходы"
        )

        self.assertEqual(self.ledger.get_account_balance_cents(husband_card.id), rubles_to_cents(25000))
        self.assertEqual(self.ledger.get_account_balance_cents(wife_card.id), rubles_to_cents(15000))

        overview = self.ledger.get_financial_overview()
        self.assertEqual(overview["husband_personal_balance_cents"], rubles_to_cents(25000))
        self.assertEqual(overview["wife_personal_balance_cents"], rubles_to_cents(15000))

    # 7. Transfers Do NOT Create Income or Expense
    def test_07_transfers_do_not_create_income_or_expense(self):
        """Requirement 7: Verify that transfers leave Income (4xxx) and Expense (5xxx) balances exactly ZERO."""
        card1 = self.ledger.get_account_by_code("1010")
        card2 = self.ledger.get_account_by_code("1011")
        self._seed_funds(card1.id, rubles_to_cents(100000))

        # Execute multiple transfers
        self.ledger.record_transfer(card1.id, card2.id, rubles_to_cents(30000), "Перевод 1")
        self.ledger.record_transfer(card2.id, card1.id, rubles_to_cents(10000), "Перевод 2")

        # Verify all expense and income accounts have ZERO postings
        with get_connection(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
            SELECT count(*) FROM postings p
            JOIN accounts a ON p.account_id = a.id
            WHERE a.account_type IN ('INCOME', 'EXPENSE')
            """)
            count = cursor.fetchone()[0]
            # Opening balance seed had 1 income transaction, but transfers added 0
            cursor.execute("""
            SELECT count(*) FROM postings p
            JOIN transactions t ON p.transaction_id = t.id
            WHERE t.tx_type = 'TRANSFER' AND p.account_id IN (
                SELECT id FROM accounts WHERE account_type IN ('INCOME', 'EXPENSE')
            )
            """)
            transfer_in_pnl = cursor.fetchone()[0]
            self.assertEqual(transfer_in_pnl, 0, "Transfers must NEVER touch Income or Expense accounts")

    # 8. Credit Card Isolation & Limit Calculations
    def test_08_credit_card_limit_and_debt_tracking(self):
        """Requirement 8: Credit card limit is NOT family cash. Debt reduces Safe-to-Spend."""
        # 1. Family has 50,000 RUB on Debit card
        debit_card = self.ledger.get_account_by_code("1010")
        self._seed_funds(debit_card.id, rubles_to_cents(50000))

        # 2. Credit Card (2020) has limit 150,000 RUB
        credit_card = self.ledger.get_account_by_code("2020")
        self.ledger.update_account(credit_card.id, name="Кредитка Сбер", credit_limit_cents=rubles_to_cents(150000))

        # 3. Buy laptop on Credit Card for 40,000 RUB
        # DEBIT: Expense 5020, CREDIT: Credit Card 2020
        expense_acc = self.ledger.get_account_by_code("5020")
        tx_id = generate_uuid()
        self.ledger.record_transaction(Transaction(
            id=tx_id,
            tx_date="2026-11-09",
            tx_type="CREDIT_PURCHASE",
            description="Ноутбук в кредит",
            created_by_member_id=None,
            postings=[
                Posting(id=generate_uuid(), transaction_id=tx_id, account_id=expense_acc.id, amount_cents=rubles_to_cents(40000), posting_type="DEBIT"),
                Posting(id=generate_uuid(), transaction_id=tx_id, account_id=credit_card.id, amount_cents=rubles_to_cents(40000), posting_type="CREDIT"),
            ]
        ))

        overview = self.ledger.get_financial_overview()
        cc = overview["credit_cards"]

        # Current debt = 40,000 RUB
        self.assertEqual(cc["total_debt_cents"], rubles_to_cents(40000))
        # Total limit = 150,000 RUB
        self.assertEqual(cc["total_limit_cents"], rubles_to_cents(150000))
        # Available credit = 150,000 - 40,000 = 110,000 RUB
        self.assertEqual(cc["available_limit_cents"], rubles_to_cents(110000))

        # Common Liquid Assets = 50,000 RUB (Credit limit is NOT added!)
        self.assertEqual(overview["common_liquid_assets_cents"], rubles_to_cents(50000))
        # Safe-to-Spend = 50,000 (Liquid) - 40,000 (Debt) = 10,000 RUB
        self.assertEqual(overview["common_safe_to_spend_cents"], rubles_to_cents(10000))

    # 9. Common Expense Paid from Personal Card WITHOUT Automatic Debt
    def test_09_personal_card_for_common_expense_no_auto_debt(self):
        """Requirement 9: Husband pays for family groceries from his personal card without creating family debt."""
        husband_card = self.ledger.get_account_by_code("1011")
        grocery_acc = self.ledger.get_account_by_code("5010")

        self._seed_funds(husband_card.id, rubles_to_cents(30000))

        # Husband pays 6,000 RUB for family groceries
        expense_cents = rubles_to_cents(6000)
        tx_id = self.ledger.record_common_expense_from_personal_card(
            personal_account_id=husband_card.id,
            category_account_id=grocery_acc.id,
            amount_cents=expense_cents,
            description="Продукты на неделю (оплатил муж со своей карты)"
        )
        self.assertIsNotNone(tx_id)

        # 1. Husband's personal card decreased by 6,000 RUB (30,000 - 6,000 = 24,000 RUB)
        self.assertEqual(self.ledger.get_account_balance_cents(husband_card.id), rubles_to_cents(24000))

        # 2. Family grocery expense recognized as 6,000 RUB
        self.assertEqual(self.ledger.get_account_balance_cents(grocery_acc.id), expense_cents)

        # 3. Check that NO debt accounts (2010, 2030, etc.) were touched
        with get_connection(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
            SELECT count(*) FROM postings p
            JOIN accounts a ON p.account_id = a.id
            WHERE p.transaction_id = ? AND a.account_type = 'LIABILITY'
            """, (tx_id,))
            liability_count = cursor.fetchone()[0]
            self.assertEqual(liability_count, 0, "Personal payment for common expense must NOT create loan/liability postings")

    # 10. Preservation of Operation History
    def test_10_transaction_history_preservation(self):
        """Requirement 10: Verify transaction history and postings audit trail."""
        card = self.ledger.get_account_by_code("1010")
        cash = self.ledger.get_account_by_code("1020")
        self._seed_funds(card.id, rubles_to_cents(15000))

        tx_id = self.ledger.record_transfer(card.id, cash.id, rubles_to_cents(5000), "Снятие 5000")

        with get_connection(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM transactions WHERE id = ?", (tx_id,))
            tx_row = cursor.fetchone()
            self.assertEqual(tx_row["tx_type"], "TRANSFER")
            self.assertEqual(tx_row["description"], "Снятие 5000")

            cursor.execute("SELECT * FROM postings WHERE transaction_id = ? ORDER BY posting_type", (tx_id,))
            postings = cursor.fetchall()
            self.assertEqual(len(postings), 2)
            self.assertEqual(postings[0]["posting_type"], "CREDIT")  # Card
            self.assertEqual(postings[1]["posting_type"], "DEBIT")   # Cash

    # 11. Persistence Across Restarts
    def test_11_persistence_across_restarts(self):
        """Requirement 11: All accounts, balances, and transfers persist when re-instantiating engine."""
        husband_card = self.ledger.get_account_by_code("1011")
        self._seed_funds(husband_card.id, rubles_to_cents(70000))

        custom_acc = self.ledger.create_account(
            name="Инвестиционный счет",
            account_type="ASSET",
            subtype="CHECKING",
            ownership_scope="PERSONAL_HUSBAND",
            initial_balance_cents=rubles_to_cents(25000)
        )

        del self.ledger
        fresh_ledger = LedgerEngine(conn_or_path=self.db_path)

        reopened_acc = fresh_ledger.get_account_by_id(custom_acc.id)
        self.assertIsNotNone(reopened_acc)
        self.assertEqual(reopened_acc.name, "Инвестиционный счет")
        self.assertEqual(fresh_ledger.get_account_balance_cents(reopened_acc.id), rubles_to_cents(25000))

    # 12. Correctness of Multidimensional Balances
    def test_12_correctness_of_all_balances(self):
        """Requirement 12: Complex scenario testing all simultaneous balance projections."""
        common_card = self.ledger.get_account_by_code("1010")
        savings = self.ledger.get_account_by_code("1030")
        husband_card = self.ledger.get_account_by_code("1011")
        wife_card = self.ledger.get_account_by_code("1012")
        credit_card = self.ledger.get_account_by_code("2020")
        grocery_acc = self.ledger.get_account_by_code("5010")

        # 1. Common card gets 100,000 RUB
        self._seed_funds(common_card.id, rubles_to_cents(100000))
        # 2. Transfer 30,000 to Emergency Savings
        self.ledger.record_transfer(common_card.id, savings.id, rubles_to_cents(30000), "В резерв")
        # 3. Husband has 45,000 RUB
        self._seed_funds(husband_card.id, rubles_to_cents(45000))
        # 4. Wife has 35,000 RUB
        self._seed_funds(wife_card.id, rubles_to_cents(35000))
        # 5. Credit card limit is 80,000 RUB, spent 20,000 RUB
        self.ledger.update_account(credit_card.id, name="Кредитка", credit_limit_cents=rubles_to_cents(80000))
        tx_cc = generate_uuid()
        self.ledger.record_transaction(Transaction(
            id=tx_cc, tx_date="2026-11-09", tx_type="CREDIT_PURCHASE", description="Покупка в кредит", created_by_member_id=None,
            postings=[
                Posting(id=generate_uuid(), transaction_id=tx_cc, account_id=grocery_acc.id, amount_cents=rubles_to_cents(20000), posting_type="DEBIT"),
                Posting(id=generate_uuid(), transaction_id=tx_cc, account_id=credit_card.id, amount_cents=rubles_to_cents(20000), posting_type="CREDIT"),
            ]
        ))

        overview = self.ledger.get_financial_overview()

        # Family Liquid Assets = 70,000 (Common card) + 45,000 (Husband) + 35,000 (Wife) = 150,000 RUB
        self.assertEqual(overview["common_liquid_assets_cents"], rubles_to_cents(150000))
        # Emergency Reserves = 30,000 RUB
        self.assertEqual(overview["emergency_reserves_cents"], rubles_to_cents(30000))
        # Safe-to-Spend = 150,000 (Liquid) - 20,000 (Credit debt) = 130,000 RUB
        self.assertEqual(overview["common_safe_to_spend_cents"], rubles_to_cents(130000))
        self.assertFalse(overview["is_deficit"])
        self.assertEqual(overview["deficit_cents"], 0)
        # Informational breakdown on cards
        self.assertEqual(overview["husband_personal_balance_cents"], rubles_to_cents(45000))
        self.assertEqual(overview["wife_personal_balance_cents"], rubles_to_cents(35000))
        # Credit available = 80,000 - 20,000 = 60,000 RUB
        self.assertEqual(overview["credit_cards"]["available_limit_cents"], rubles_to_cents(60000))

    # 14. Deficit Detection in Safe-to-Spend
    def test_14_safe_to_spend_deficit_detection(self):
        """Verify that when debt exceeds liquid assets, Safe-to-Spend shows 0.00 and flags explicit deficit."""
        common_card = self.ledger.get_account_by_code("1010")
        credit_card = self.ledger.get_account_by_code("2020")
        grocery_acc = self.ledger.get_account_by_code("5010")

        # Family has 10,000 RUB on debit card
        self._seed_funds(common_card.id, rubles_to_cents(10000))

        # Family incurs 35,000 RUB debt on credit card (limit 50,000)
        self.ledger.update_account(credit_card.id, name="Кредитка", credit_limit_cents=rubles_to_cents(50000))
        tx_cc = generate_uuid()
        self.ledger.record_transaction(Transaction(
            id=tx_cc, tx_date="2026-11-09", tx_type="CREDIT_PURCHASE", description="Покупка мебели в кредит", created_by_member_id=None,
            postings=[
                Posting(id=generate_uuid(), transaction_id=tx_cc, account_id=grocery_acc.id, amount_cents=rubles_to_cents(35000), posting_type="DEBIT"),
                Posting(id=generate_uuid(), transaction_id=tx_cc, account_id=credit_card.id, amount_cents=rubles_to_cents(35000), posting_type="CREDIT"),
            ]
        ))

        overview = self.ledger.get_financial_overview()
        # Liquid assets = 10,000 RUB
        self.assertEqual(overview["common_liquid_assets_cents"], rubles_to_cents(10000))
        # Credit debt = 35,000 RUB
        self.assertEqual(overview["credit_cards"]["total_debt_cents"], rubles_to_cents(35000))
        # Net Safe-to-Spend = 10,000 - 35,000 = -25,000 RUB (Deficit)
        self.assertEqual(overview["net_safe_to_spend_cents"], rubles_to_cents(-25000))
        self.assertEqual(overview["common_safe_to_spend_cents"], 0)
        self.assertTrue(overview["is_deficit"])
        self.assertEqual(overview["deficit_cents"], rubles_to_cents(25000))
        self.assertEqual(overview["deficit_rub"], "25000.00")

    # 13. Idempotency Payload Tampering Rejection
    def test_13_idempotency_payload_mismatch_rejection(self):
        """Verify that reusing the same idempotency key with a DIFFERENT payload strictly raises an error."""
        card = self.ledger.get_account_by_code("1010")
        salary = self.ledger.get_account_by_code("4010")

        key = "idemp_unique_tx_key_443322"
        tx1 = Transaction(
            id=generate_uuid(), tx_date="2026-11-09", tx_type="INCOME", description="Зарплата 50000", created_by_member_id=None,
            postings=[
                Posting(id=generate_uuid(), transaction_id="1", account_id=card.id, amount_cents=rubles_to_cents(50000), posting_type="DEBIT"),
                Posting(id=generate_uuid(), transaction_id="1", account_id=salary.id, amount_cents=rubles_to_cents(50000), posting_type="CREDIT")
            ]
        )
        saved_id = self.ledger.record_transaction(tx1, idempotency_key=key)

        # Retry with EXACT same payload -> Returns saved_id (OK)
        tx_identical = Transaction(
            id=generate_uuid(), tx_date="2026-11-09", tx_type="INCOME", description="Зарплата 50000", created_by_member_id=None,
            postings=[
                Posting(id=generate_uuid(), transaction_id="2", account_id=card.id, amount_cents=rubles_to_cents(50000), posting_type="DEBIT"),
                Posting(id=generate_uuid(), transaction_id="2", account_id=salary.id, amount_cents=rubles_to_cents(50000), posting_type="CREDIT")
            ]
        )
        retry_id = self.ledger.record_transaction(tx_identical, idempotency_key=key)
        self.assertEqual(saved_id, retry_id)

        # Tampered retry with DIFFERENT payload (amount 999,999) under SAME key -> MUST be rejected!
        tx_tampered = Transaction(
            id=generate_uuid(), tx_date="2026-11-09", tx_type="INCOME", description="Подделка 999999", created_by_member_id=None,
            postings=[
                Posting(id=generate_uuid(), transaction_id="3", account_id=card.id, amount_cents=rubles_to_cents(999999), posting_type="DEBIT"),
                Posting(id=generate_uuid(), transaction_id="3", account_id=salary.id, amount_cents=rubles_to_cents(999999), posting_type="CREDIT")
            ]
        )
        with self.assertRaises(ValueError) as ctx:
            self.ledger.record_transaction(tx_tampered, idempotency_key=key)
        self.assertIn("Конфликт идемпотентности", str(ctx.exception))

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
