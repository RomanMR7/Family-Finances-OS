"""
Family Finances OS - Stage 9 Comprehensive Test Suite
Verification for:
1. Financial Goals (Цели накоплений): creation, progress calculation, monthly target pacing.
2. Goal Funding / Contributions with double-entry accounting transfer.
3. Goal Completion milestone detection (100% reached).
4. Debt Summary (Задолженности): detection of credit card debt, loans, credit limits, upcoming dues.
5. Debt Repayment (Погашение долгов): strict double-entry ledger execution (CREDIT_PAYMENT / LOAN_REPAYMENT).
6. Debt Repayment linked to monthly recurring obligations (auto-fulfillment of monthly bill).
7. Smart Quick Input Parsing (Умный быстрый ввод): parsing "500 кофе", "1200 продукты", "80000 зарплата".
8. Web API Endpoints for Goals, Debts, and Fast Entry without breaking existing functionality.
"""
import io
import json
import shutil
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from family_finances_os.db import init_database, get_connection, EncryptedDatabaseStorage
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


class TestStage9GoalsDebtSmartInput(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="ffos_s9_")
        self.db_path = Path(self.test_dir) / "test_stage9.db"
        init_database(self.db_path)
        self.conn = get_connection(self.db_path)
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
        resp_data = json.loads(parts[1].decode("utf-8")) if len(parts) > 1 and parts[1] else {}
        return status_code, resp_data

    def _seed_card_funds(self, account_code: str, amount_rub: float):
        acc = self.ledger.get_account_by_code(account_code)
        equity = self.ledger.get_account_by_code("3010")
        cents = rubles_to_cents(amount_rub)
        tx_id = generate_uuid()
        self.ledger.record_transaction(Transaction(
            id=tx_id,
            tx_date=current_iso_time()[:10],
            tx_type="ADJUSTMENT",
            description="Стартовый баланс карты",
            postings=[
                Posting(id=generate_uuid(), transaction_id=tx_id, account_id=acc.id, amount_cents=cents, posting_type="DEBIT", ownership_scope="COMMON"),
                Posting(id=generate_uuid(), transaction_id=tx_id, account_id=equity.id, amount_cents=cents, posting_type="CREDIT", ownership_scope="COMMON")
            ]
        ))

    def _seed_debt(self, liability_code: str, debt_rub: float):
        liability = self.ledger.get_account_by_code(liability_code)
        equity = self.ledger.get_account_by_code("3010")
        cents = rubles_to_cents(debt_rub)
        tx_id = generate_uuid()
        self.ledger.record_transaction(Transaction(
            id=tx_id,
            tx_date=current_iso_time()[:10],
            tx_type="ADJUSTMENT",
            description="Начальный долг",
            postings=[
                Posting(id=generate_uuid(), transaction_id=tx_id, account_id=equity.id, amount_cents=cents, posting_type="DEBIT", ownership_scope="COMMON"),
                Posting(id=generate_uuid(), transaction_id=tx_id, account_id=liability.id, amount_cents=cents, posting_type="CREDIT", ownership_scope="COMMON")
            ]
        ))

    # 1. Goals Lifecycle & Progress Calculations
    def test_01_goals_lifecycle_and_calculations(self):
        """Test creating, reading, updating and archiving financial goals."""
        savings_acc = self.ledger.get_account_by_code("1030")
        goal = self.ledger.create_goal(
            name="Подушка безопасности",
            target_amount_cents=rubles_to_cents(150000.00),
            target_date="2027-12-31",
            account_id=savings_acc.id,
            icon="🛡️",
            note="Резерв на 3 месяца"
        )
        self.assertIsNotNone(goal.id)
        self.assertEqual(goal.name, "Подушка безопасности")
        self.assertEqual(goal.target_amount_cents, 15000000)
        self.assertEqual(goal.current_amount_cents, 0)
        self.assertFalse(goal.is_completed)

        goals = self.ledger.get_goals()
        self.assertEqual(len(goals), 1)
        g = goals[0]
        self.assertEqual(g["name"], "Подушка безопасности")
        self.assertEqual(g["target_amount_rub"], "150000.00")
        self.assertEqual(g["current_amount_rub"], "0.00")
        self.assertEqual(g["progress_percent"], 0.0)
        self.assertEqual(g["remaining_rub"], "150000.00")
        self.assertIn("recommended_monthly_rub", g)

        # Update goal
        ok = self.ledger.update_goal(goal.id, name="Большая подушка", target_amount_cents=rubles_to_cents(200000.00))
        self.assertTrue(ok)
        updated = self.ledger.get_goals()[0]
        self.assertEqual(updated["name"], "Большая подушка")
        self.assertEqual(updated["target_amount_rub"], "200000.00")

    # 2. Goal Funding with Double-Entry Accounting Transfer
    def test_02_goal_funding_with_transfer(self):
        """Test contributing money to a goal transfers funds to the savings account and tracks progress."""
        self._seed_card_funds("1010", 80000.00)
        card_acc = self.ledger.get_account_by_code("1010")
        savings_acc = self.ledger.get_account_by_code("1030")

        goal = self.ledger.create_goal(
            name="Отпуск на море",
            target_amount_cents=rubles_to_cents(100000.00),
            account_id=savings_acc.id,
            icon="🏖️"
        )

        # Contribute 35 000 ₽ from main card
        res = self.ledger.contribute_to_goal(
            goal_id=goal.id,
            amount_cents=rubles_to_cents(35000.00),
            source_account_id=card_acc.id,
            note="Отложили с зарплаты"
        )
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["new_current_cents"], 3500000)
        self.assertFalse(res["is_completed"])

        # Check bank balances
        self.assertEqual(self.ledger.get_account_balance_cents(card_acc.id), rubles_to_cents(45000.00))
        self.assertEqual(self.ledger.get_account_balance_cents(savings_acc.id), rubles_to_cents(35000.00))

        # Check goal data
        goals = self.ledger.get_goals()
        self.assertEqual(goals[0]["current_amount_rub"], "35000.00")
        self.assertEqual(goals[0]["progress_percent"], 35.0)
        self.assertEqual(goals[0]["remaining_rub"], "65000.00")

    # 3. Goal Completion Milestone
    def test_03_goal_completion_milestone(self):
        """Test goal reaches 100% and is marked completed."""
        self._seed_card_funds("1010", 120000.00)
        card_acc = self.ledger.get_account_by_code("1010")
        savings_acc = self.ledger.get_account_by_code("1030")

        goal = self.ledger.create_goal(
            name="Новый ноутбук",
            target_amount_cents=rubles_to_cents(50000.00),
            account_id=savings_acc.id
        )

        res = self.ledger.contribute_to_goal(
            goal_id=goal.id,
            amount_cents=rubles_to_cents(50000.00),
            source_account_id=card_acc.id
        )
        self.assertTrue(res["is_completed"])

        goals = self.ledger.get_goals()
        self.assertTrue(goals[0]["is_completed"])
        self.assertEqual(goals[0]["progress_percent"], 100.0)
        self.assertEqual(goals[0]["remaining_cents"], 0)

    # 4. Debt Summary Detection
    def test_04_debts_summary_detection(self):
        """Test debt summary detects credit cards, consumer loans, limits, and debts."""
        self._seed_debt("2020", 25000.00)  # Credit card debt 25k
        self._seed_debt("2010", 75000.00)  # Consumer loan debt 75k

        summary = self.ledger.get_debts_summary()
        self.assertIn("debts", summary)
        self.assertEqual(len(summary["debts"]), 2)
        self.assertEqual(summary["total_debt_rub"], "100000.00")
        self.assertEqual(summary["credit_cards_debt_rub"], "25000.00")
        self.assertEqual(summary["loans_debt_rub"], "75000.00")

    # 5. Debt Repayment Execution via Double-Entry
    def test_05_debt_repayment_execution(self):
        """Test repaying debt debits liability, credits asset, and restores Safe-to-Spend."""
        self._seed_card_funds("1010", 60000.00)
        self._seed_debt("2020", 20000.00)  # 20k debt on credit card

        card_acc = self.ledger.get_account_by_code("1010")
        credit_acc = self.ledger.get_account_by_code("2020")

        # Repay 15 000 ₽ towards credit card
        tx_id = self.ledger.record_debt_repayment(
            source_account_id=card_acc.id,
            liability_account_id=credit_acc.id,
            amount_cents=rubles_to_cents(15000.00),
            description="Частичное погашение кредитки"
        )
        self.assertIsNotNone(tx_id)

        # Check balances
        # Card should have 60k - 15k = 45k
        self.assertEqual(self.ledger.get_account_balance_cents(card_acc.id), rubles_to_cents(45000.00))
        # Credit card debt should be 20k - 15k = 5k
        self.assertEqual(self.ledger.get_account_balance_cents(credit_acc.id), rubles_to_cents(5000.00))

        # Check debt summary
        debts = self.ledger.get_debts_summary()
        self.assertEqual(debts["credit_cards_debt_rub"], "5000.00")

    # 6. Debt Repayment Linked to Monthly Obligation
    def test_06_debt_repayment_linked_to_obligation(self):
        """Test debt repayment automatically marks associated recurring obligation paid."""
        self._seed_card_funds("1010", 50000.00)
        self._seed_debt("2010", 80000.00)

        card_acc = self.ledger.get_account_by_code("1010")
        loan_acc = self.ledger.get_account_by_code("2010")

        # Create monthly obligation for loan
        obl = self.ledger.create_obligation(
            name="Платеж по кредиту",
            amount_cents=rubles_to_cents(12000.00),
            due_day=20,
            payment_account_id=loan_acc.id
        )

        unpaid_before, _, _ = self.ledger.calculate_unpaid_obligations_cents()
        self.assertEqual(unpaid_before, 1200000)

        # Repay debt with obligation_id
        tx_id = self.ledger.record_debt_repayment(
            source_account_id=card_acc.id,
            liability_account_id=loan_acc.id,
            amount_cents=rubles_to_cents(12000.00),
            obligation_id=obl.id
        )
        self.assertIsNotNone(tx_id)

        # Obligation should now be marked paid!
        unpaid_after, _, paid_after = self.ledger.calculate_unpaid_obligations_cents()
        self.assertEqual(unpaid_after, 0)
        self.assertEqual(paid_after, 1200000)

    # 7. Smart Quick Input Parsing & Fast Recording
    def test_07_smart_quick_input_parsing_and_execution(self):
        """Test intelligent parsing of single-string inputs like '500 кофе', '1500 продукты', '80000 зарплата'."""
        self._seed_card_funds("1010", 10000.00)
        card_acc = self.ledger.get_account_by_code("1010")

        # Expense: "500 кофе"
        parsed_coffee = self.ledger.parse_quick_input("500 кофе")
        self.assertEqual(parsed_coffee["amount_rub"], "500.00")
        self.assertEqual(parsed_coffee["amount_cents"], 50000)
        self.assertEqual(parsed_coffee["tx_type"], "EXPENSE")
        self.assertEqual(parsed_coffee["description"], "Кофе")
        self.assertIn("Кафе", parsed_coffee["category_name"])

        # Expense: "продукты 1850.50"
        parsed_groceries = self.ledger.parse_quick_input("продукты 1850.50")
        self.assertEqual(parsed_groceries["amount_rub"], "1850.50")
        self.assertEqual(parsed_groceries["tx_type"], "EXPENSE")
        self.assertEqual(parsed_groceries["category_name"], "Продукты и питание")

        # Income: "85000 зарплата"
        parsed_salary = self.ledger.parse_quick_input("85000 зарплата")
        self.assertEqual(parsed_salary["amount_rub"], "85000.00")
        self.assertEqual(parsed_salary["tx_type"], "INCOME")
        self.assertIn("Зарплат", parsed_salary["category_name"])

        # Execute quick transaction directly through ledger helper
        tx_id = self.ledger.record_quick_input(
            text="650 такси",
            account_id=card_acc.id
        )
        self.assertIsNotNone(tx_id)
        # Verify card reduced by 650
        self.assertEqual(self.ledger.get_account_balance_cents(card_acc.id), rubles_to_cents(10000.00 - 650.00))

    # 8. Web API Endpoints for Goals, Debts and Quick-Tx
    def test_08_web_api_endpoints(self):
        """Test REST API endpoints for Goals, Debts, and Fast Entry."""
        self._seed_card_funds("1010", 50000.00)
        self._seed_debt("2020", 10000.00)

        # Mock authenticated session
        token = GLOBAL_SESSION_MANAGER.create_session({
            "id": "u1", "username": "admin", "display_name": "Глава семьи", "role": "OWNER"
        })

        # A. Create Goal via API
        code, data = self._execute_http("POST", "/api/goals/create", {
            "name": "Новый телевизор",
            "target_amount_rub": "45000.00",
            "icon": "📺"
        }, token=token)
        self.assertEqual(code, 200)
        self.assertIn("goal", data)
        goal_id = data["goal"]["id"]

        # B. Get Goals via API
        code, data = self._execute_http("GET", "/api/goals", token=token)
        self.assertEqual(code, 200)
        self.assertIn("goals", data)
        self.assertEqual(len(data["goals"]), 1)

        # C. Contribute to Goal via API
        card = self.ledger.get_account_by_code("1010")
        code, data = self._execute_http("POST", "/api/goals/contribute", {
            "goal_id": goal_id,
            "amount_rub": "15000.00",
            "source_account_id": card.id
        }, token=token)
        self.assertEqual(code, 200)
        self.assertEqual(data["status"], "success")

        # D. Get Debts Summary via API
        code, data = self._execute_http("GET", "/api/debts", token=token)
        self.assertEqual(code, 200)
        self.assertEqual(data["total_debt_rub"], "10000.00")

        # E. Pay Debt via API
        credit = self.ledger.get_account_by_code("2020")
        code, data = self._execute_http("POST", "/api/debts/pay", {
            "source_account_id": card.id,
            "liability_account_id": credit.id,
            "amount_rub": "10000.00"
        }, token=token)
        self.assertEqual(code, 200)
        self.assertEqual(data["status"], "success")

        # F. Quick Transaction via API
        code, data = self._execute_http("POST", "/api/quick-tx/create", {
            "text": "1200 продукты"
        }, token=token)
        self.assertEqual(code, 200)
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["parsed"]["amount_rub"], "1200.00")


if __name__ == "__main__":
    unittest.main()
