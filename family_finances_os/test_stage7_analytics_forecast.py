"""
Family Finances OS - Stage 7 Comprehensive Verification Test Suite
Tests all requirements of Stage 7 (Variant 2):
1. Spending Analytics: Category breakdown (ranking, amounts, percentages).
2. Spending Analytics: Family member attribution (Common, Husband, Wife).
3. Savings Rate % Calculation and edge cases (Zero Income, Deficit Spending).
4. 30/60/90-Day Cash Flow Projection Engine (Net Liquid Day 0, daily steps).
5. Predictive Cash Gap Detection (pinpoints exact deficit date, amount, and triggering obligation).
6. Obligation payment isolation (already paid in current month is not double-deducted).
7. Web API Endpoints: GET /api/analytics/summary & GET /api/forecast/cashflow.
"""
import io
import json
import shutil
import tempfile
import unittest
from datetime import datetime, timedelta
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


class TestStage7AnalyticsAndForecast(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="ffos_s7_")
        self.db_path = Path(self.test_dir) / "test_stage7.db"
        init_database(self.db_path)
        self.ledger = LedgerEngine(conn_or_path=self.db_path)
        self.ledger.seed_default_chart_of_accounts()
        self.ledger.seed_default_categories()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _seed_income(self, account_id: str, amount_cents: int, tx_date: str = "2026-11-05"):
        salary_acc = self.ledger.get_account_by_code("4010")
        tx_id = generate_uuid()
        self.ledger.record_transaction(Transaction(
            id=tx_id,
            tx_date=tx_date,
            tx_type="INCOME",
            description="Зарплата семьи",
            created_by_member_id=None,
            postings=[
                Posting(id=generate_uuid(), transaction_id=tx_id, account_id=account_id, amount_cents=amount_cents, posting_type="DEBIT"),
                Posting(id=generate_uuid(), transaction_id=tx_id, account_id=salary_acc.id, amount_cents=amount_cents, posting_type="CREDIT"),
            ]
        ))

    def _seed_expense(self, account_id: str, amount_cents: int, category_id: str, description: str, tx_date: str = "2026-11-06", scope: str = "COMMON"):
        expense_acc = self.ledger.get_account_by_code("5010")
        tx_id = generate_uuid()
        self.ledger.record_transaction(Transaction(
            id=tx_id,
            tx_date=tx_date,
            tx_type="EXPENSE",
            description=description,
            created_by_member_id=None,
            postings=[
                Posting(id=generate_uuid(), transaction_id=tx_id, account_id=expense_acc.id, amount_cents=amount_cents, posting_type="DEBIT", category_id=category_id, ownership_scope=scope),
                Posting(id=generate_uuid(), transaction_id=tx_id, account_id=account_id, amount_cents=amount_cents, posting_type="CREDIT", ownership_scope=scope),
            ]
        ))

    # 1. Category Breakdown & Totals
    def test_01_analytics_category_breakdown_and_totals(self):
        """Verify income, expenses, category ranking and percentages."""
        card = self.ledger.get_account_by_code("1010")
        self._seed_income(card.id, rubles_to_cents(100000))

        cat_food = self.ledger.create_category("Супермаркеты", "EXPENSE", icon="🛒")
        cat_pharm = self.ledger.create_category("Аптека", "EXPENSE", icon="💊")
        cat_auto = self.ledger.create_category("Бензин и АЗС", "EXPENSE", icon="⛽")

        # 15,000 + 5,000 + 10,000 = 30,000 RUB expense
        self._seed_expense(card.id, rubles_to_cents(15000), cat_food.id, "Продукты на неделю")
        self._seed_expense(card.id, rubles_to_cents(5000), cat_pharm.id, "Лекарства")
        self._seed_expense(card.id, rubles_to_cents(10000), cat_auto.id, "Заправка авто")

        analytics = self.ledger.get_spending_analytics(period="all")
        self.assertEqual(analytics["total_income_cents"], rubles_to_cents(100000))
        self.assertEqual(analytics["total_expense_cents"], rubles_to_cents(30000))
        self.assertEqual(analytics["net_savings_cents"], rubles_to_cents(70000))
        self.assertEqual(analytics["savings_rate_percent"], 70.0)

        # Check category ranking
        cats = analytics["categories"]
        self.assertEqual(len(cats), 3)
        self.assertEqual(cats[0]["name"], "Супермаркеты")
        self.assertEqual(cats[0]["amount_cents"], rubles_to_cents(15000))
        self.assertEqual(cats[0]["percent"], 50.0)

        self.assertEqual(cats[1]["name"], "Бензин и АЗС")
        self.assertEqual(cats[1]["amount_cents"], rubles_to_cents(10000))
        self.assertEqual(cats[1]["percent"], 33.3)

        self.assertEqual(cats[2]["name"], "Аптека")
        self.assertEqual(cats[2]["amount_cents"], rubles_to_cents(5000))
        self.assertEqual(cats[2]["percent"], 16.7)

    # 2. Member Attribution Breakdown
    def test_02_analytics_member_attribution(self):
        """Verify spending attribution across Common, Husband, and Wife."""
        card_common = self.ledger.get_account_by_code("1010")
        card_husband = self.ledger.get_account_by_code("1011")
        card_wife = self.ledger.get_account_by_code("1012")

        self._seed_income(card_common.id, rubles_to_cents(80000))
        cat = self.ledger.create_category("Общие нужды", "EXPENSE")

        # Common: 25,000 (50%), Husband: 15,000 (30%), Wife: 10,000 (20%) -> Total 50,000
        self._seed_expense(card_common.id, rubles_to_cents(25000), cat.id, "Бытовая техника", scope="COMMON")
        self._seed_expense(card_husband.id, rubles_to_cents(15000), cat.id, "Личные мужа", scope="PERSONAL_HUSBAND")
        self._seed_expense(card_wife.id, rubles_to_cents(10000), cat.id, "Личные жены", scope="PERSONAL_WIFE")

        analytics = self.ledger.get_spending_analytics(period="all")
        members = {m["scope"]: m for m in analytics["members"]}

        self.assertEqual(members["COMMON"]["amount_cents"], rubles_to_cents(25000))
        self.assertEqual(members["COMMON"]["percent"], 50.0)
        self.assertEqual(members["PERSONAL_HUSBAND"]["amount_cents"], rubles_to_cents(15000))
        self.assertEqual(members["PERSONAL_HUSBAND"]["percent"], 30.0)
        self.assertEqual(members["PERSONAL_WIFE"]["amount_cents"], rubles_to_cents(10000))
        self.assertEqual(members["PERSONAL_WIFE"]["percent"], 20.0)

    # 3. Savings Rate Edge Cases: Zero Income & Deficit Spending
    def test_03_analytics_edge_cases_zero_income_and_deficit(self):
        """Confirm savings rate handles zero income and deficit without ZeroDivisionError."""
        card = self.ledger.get_account_by_code("1010")
        cat = self.ledger.create_category("Развлечения", "EXPENSE")

        # Scenario A: Expense only, 0 income
        self._seed_expense(card.id, rubles_to_cents(20000), cat.id, "Кино и ужин")
        an_zero = self.ledger.get_spending_analytics(period="all")
        self.assertEqual(an_zero["total_income_cents"], 0)
        self.assertEqual(an_zero["total_expense_cents"], rubles_to_cents(20000))
        self.assertEqual(an_zero["savings_rate_percent"], 0.0)

        # Scenario B: Income 10,000, Expense 15,000 (Living in deficit)
        self._seed_income(card.id, rubles_to_cents(10000))
        an_def = self.ledger.get_spending_analytics(period="all")
        # Income = 10,000, Expense = 20,000 -> Net = -10,000 -> Rate = -100.0%
        self.assertEqual(an_def["total_income_cents"], rubles_to_cents(10000))
        self.assertEqual(an_def["total_expense_cents"], rubles_to_cents(20000))
        self.assertEqual(an_def["savings_rate_percent"], -100.0)

    # 4. Cash Flow Forecast: Baseline Trajectory
    def test_04_cash_flow_forecast_baseline_trajectory(self):
        """Verify daily simulation trajectory from Net Liquid starting point."""
        card = self.ledger.get_account_by_code("1010")
        # 60,000 RUB on debit card
        self._seed_income(card.id, rubles_to_cents(60000))

        forecast = self.ledger.get_cash_flow_forecast(days=30, include_burn_rate=False)
        self.assertEqual(forecast["forecast_days"], 30)
        self.assertEqual(forecast["starting_liquid_cents"], rubles_to_cents(60000))
        self.assertEqual(forecast["credit_debt_cents"], 0)
        self.assertEqual(forecast["effective_start_cents"], rubles_to_cents(60000))
        self.assertFalse(forecast["has_deficit"])
        self.assertIsNone(forecast["first_deficit_date"])
        self.assertEqual(len(forecast["timeline"]), 30)
        # All days remain at 60,000 RUB because no obligations
        self.assertEqual(forecast["timeline"][-1]["balance_cents"], rubles_to_cents(60000))

    # 5. Predictive Cash Gap Detection (Exact date & amount)
    def test_05_predictive_cash_gap_detection(self):
        """Verify simulation correctly detects hard cash gap when obligation exceeds liquidity."""
        card = self.ledger.get_account_by_code("1010")
        credit_card = self.ledger.get_account_by_code("2020")
        expense_acc = self.ledger.get_account_by_code("5010")

        # 40,000 RUB liquid funds
        self._seed_income(card.id, rubles_to_cents(40000))

        # 10,000 RUB credit card debt
        tx_cc = Transaction(
            id=generate_uuid(),
            tx_date="2026-11-07",
            tx_type="EXPENSE",
            description="Покупка в кредит",
            created_by_member_id=None,
            postings=[
                Posting(id=generate_uuid(), transaction_id="1", account_id=expense_acc.id, amount_cents=rubles_to_cents(10000), posting_type="DEBIT"),
                Posting(id=generate_uuid(), transaction_id="1", account_id=credit_card.id, amount_cents=rubles_to_cents(10000), posting_type="CREDIT"),
            ]
        )
        self.ledger.record_transaction(tx_cc)

        # Net starting liquidity: 40,000 - 10,000 = 30,000 RUB
        # Create recurring obligation: 35,000 RUB due on day 15
        today = datetime.now().date()
        target_day = (today + timedelta(days=10)).day
        self.ledger.create_obligation(
            name="Аренда квартиры",
            amount_cents=rubles_to_cents(35000),
            due_day=target_day
        )

        forecast = self.ledger.get_cash_flow_forecast(days=30, include_burn_rate=False)
        self.assertEqual(forecast["effective_start_cents"], rubles_to_cents(30000))
        self.assertTrue(forecast["has_deficit"], "Deficit must be detected when 35,000 > 30,000")
        self.assertIsNotNone(forecast["first_deficit_date"])
        # Expected deficit: 30,000 - 35,000 = -5,000 RUB (500000 cents)
        self.assertEqual(forecast["first_deficit_cents"], rubles_to_cents(5000))
        self.assertEqual(forecast["first_deficit_rub"], "5000.00")
        self.assertIn("Аренда", forecast["first_deficit_trigger"])

    # 6. Paid Obligation Isolation in Current Month
    def test_06_paid_obligation_isolation_in_current_month(self):
        """Confirm that obligations already paid in the current month are NOT double-deducted."""
        card = self.ledger.get_account_by_code("1010")
        self._seed_income(card.id, rubles_to_cents(50000))

        today = datetime.now().date()
        target_day = (today + timedelta(days=5)).day
        curr_month = today.strftime("%Y-%m")

        obl = self.ledger.create_obligation(name="Кредит на ремонт", amount_cents=rubles_to_cents(12000), due_day=target_day)
        # Mark as paid this month
        self.ledger.mark_obligation_paid(obl.id, month_year=curr_month)

        forecast = self.ledger.get_cash_flow_forecast(days=30, include_burn_rate=False)
        # Because target_day is in current month and is paid, it should NOT deduct in current month!
        # Thus balance after 5 days should remain 50,000 RUB
        day_5_point = forecast["timeline"][4]  # 5th day in horizon
        if (today + timedelta(days=5)).strftime("%Y-%m") == curr_month:
            self.assertEqual(day_5_point["balance_cents"], rubles_to_cents(50000))

    # 7. Web API Endpoints: /api/analytics/summary & /api/forecast/cashflow
    def test_07_web_api_endpoints(self):
        """Verify HTTP 200 responses and structure of analytics and forecast API."""
        valid_token = GLOBAL_SESSION_MANAGER.create_session({"user_id": "u_test", "username": "admin", "role": "OWNER"})

        def _exec_get(path: str):
            req = f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {valid_token}\r\n\r\n".encode()
            sock = MockSocket(req)
            FamilyFinancesHandler(sock, ("127.0.0.1", 12345), None)
            headers, body = bytes(sock.output).split(b"\r\n\r\n", 1)
            status_line = headers.split(b"\r\n")[0].decode()
            return status_line, json.loads(body.decode("utf-8"))

        # 1. /api/analytics/summary
        status, data = _exec_get("/api/analytics/summary?period=current_month")
        self.assertIn("200 OK", status)
        self.assertIn("total_expense_rub", data)
        self.assertIn("categories", data)
        self.assertIn("members", data)

        # 2. /api/forecast/cashflow
        status_fc, data_fc = _exec_get("/api/forecast/cashflow?days=30&include_burn=1")
        self.assertIn("200 OK", status_fc)
        self.assertIn("starting_liquid_rub", data_fc)
        self.assertIn("timeline", data_fc)
        self.assertIn("has_deficit", data_fc)


if __name__ == "__main__":
    unittest.main(verbosity=2)
