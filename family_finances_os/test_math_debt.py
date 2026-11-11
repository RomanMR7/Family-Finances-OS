"""Economic regressions for debt estimates and real principal repayments."""
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from family_finances_os.db import init_database, get_connection
from family_finances_os.ledger import LedgerEngine


class TestDebtMath(unittest.TestCase):
    def setUp(self):
        self.folder = Path(tempfile.mkdtemp(prefix="ffos_math_debt_"))
        self.path = self.folder / "ledger.db"
        init_database(self.path)
        self.conn = get_connection(self.path)
        self.ledger = LedgerEngine(self.conn)
        self.ledger.seed_default_chart_of_accounts()
        self.ledger.seed_default_categories()

    def tearDown(self):
        self.conn.close()
        shutil.rmtree(self.folder, ignore_errors=True)

    def scenario(self, debt=100000, **kwargs):
        return self.ledger.calculate_credit_payoff_scenarios(debt, as_of_date="2026-11-11", **kwargs)

    def funded_debt(self, debt=100000, monthly=0):
        source = self.ledger.create_account("Source", "ASSET", "CHECKING", "COMMON", initial_balance_cents=200000)
        created = self.ledger.create_debt("Debt", subtype="CREDIT_CARD", initial_debt_cents=debt,
                                          monthly_payment_cents=monthly, due_day=20 if monthly else None,
                                          interest_rate_percent=0)
        return source.id, created

    def test_zero_debt(self):
        result = self.scenario(0)
        self.assertEqual(result["minimum_scenario"]["months_to_payoff"], 0)
        self.assertFalse(result["grace_scenario"]["is_active"])
        self.assertEqual(result["minimum_scenario"]["total_interest_cents"], 0)

    def test_zero_apr_and_one_cent_payment(self):
        s = self.scenario(100, interest_rate_percent=0, custom_payment_cents=1)["custom_scenario"]
        self.assertEqual(s["monthly_payment_cents"], 1)
        self.assertEqual(s["months_to_payoff"], 100)
        self.assertEqual(s["total_paid_cents"], 100)
        self.assertEqual(s["total_interest_cents"], 0)

    def test_half_up_monthly_interest(self):
        s = self.scenario(100, interest_rate_percent=6, custom_payment_cents=100)["custom_scenario"]
        self.assertEqual(s["total_interest_cents"], 1)
        self.assertEqual([x["payment_cents"] for x in s["schedule"]], [100, 1])

    def test_accelerated_integer_schedule_fully_reconciles(self):
        for amount in (1, 100, 101, 10000000):
            for scenario in self.scenario(amount, interest_rate_percent=24.8)["accelerated_scenarios"]:
                self.assertTrue(scenario["paid_off"])
                self.assertEqual(scenario["remaining_cents"], 0)
                self.assertLessEqual(scenario["months_to_payoff"], scenario["months"])
                schedule = scenario["schedule"]
                self.assertEqual(sum(x["payment_cents"] for x in schedule), amount + sum(x["interest_cents"] for x in schedule))
                self.assertTrue(all(x["payment_cents"] > 0 for x in schedule))

    def test_horizon_is_not_fake_payoff(self):
        s = self.scenario(10000000, interest_rate_percent=0, custom_payment_cents=100)["custom_scenario"]
        self.assertEqual(s["status"], "HORIZON_LIMIT")
        self.assertEqual(s["remaining_cents"], 9964000)
        self.assertFalse(s["paid_off"])
        self.assertIsNone(s["months_to_payoff"])
        self.assertIsNone(s["payoff_date"])
        self.assertIsNone(s["total_interest_cents"])
        self.assertIsNone(s["interest_savings_cents"])

    def test_non_amortizing_has_no_date_or_fake_savings(self):
        s = self.scenario(1000000, interest_rate_percent=12, custom_payment_cents=1000)["custom_scenario"]
        self.assertEqual(s["status"], "NON_AMORTIZING")
        self.assertFalse(s["paid_off"])
        self.assertIsNone(s["payoff_date"])
        self.assertIsNone(s["interest_savings_rub"])
        self.assertEqual(s["remaining_cents"], 1009000)

    def test_minimum_matches_applied_first_payment(self):
        s = self.scenario(10000000, interest_rate_percent=60, min_payment_percent=3)["minimum_scenario"]
        self.assertEqual(s["first_payment_cents"], 300000)
        self.assertEqual(s["schedule"][0]["payment_cents"], s["first_payment_cents"])
        self.assertEqual(s["status"], "NON_AMORTIZING")
        small = self.scenario(10000, interest_rate_percent=24.8)["minimum_scenario"]
        banking = self.ledger.calculate_credit_card_banking_metrics(10000)
        self.assertEqual(small["first_payment_cents"], banking["min_payment_cents"])

    def test_unknown_grace_does_not_claim_free_credit(self):
        s = self.ledger.calculate_credit_card_banking_metrics(100000)
        self.assertEqual(s["status"], "UNKNOWN")
        self.assertFalse(s["payoff_scenarios"]["grace_scenario"]["is_active"])
        self.assertIsNone(s["payoff_scenarios"]["grace_scenario"]["total_interest_cents"])

    def test_invalid_rates_and_dates_reject_without_creating_debt(self):
        before = len(self.ledger.get_debts_summary()["debts"])
        for kwargs in ({"interest_rate_percent": -1}, {"interest_rate_percent": float("nan")},
                       {"late_penalty_rate_percent": float("inf")}, {"min_payment_percent": -3},
                       {"grace_due_date": "2026-13-01"}, {"initial_debt_cents": 1.5}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.ledger.create_debt("Invalid", subtype="CREDIT_CARD", **kwargs)
        self.assertEqual(len(self.ledger.get_debts_summary()["debts"]), before)

    def test_zero_settings_preserved(self):
        _, debt = self.funded_debt()
        self.ledger.update_credit_card_settings(debt["account_id"], interest_rate_percent=0,
             late_penalty_rate_percent=0, min_payment_percent=0, grace_period_days=0, credit_limit_cents=0)
        card = next(x for x in self.ledger.get_debts_summary()["debts"] if x["id"] == debt["account_id"])
        self.assertEqual(card["banking"]["interest_rate_percent"], 0)
        self.assertEqual(card["banking"]["late_penalty_rate_percent"], 0)
        self.assertEqual(card["banking"]["grace_period_days"], 0)

    def test_repayment_overpay_rejected_and_networth_conserved(self):
        source, debt = self.funded_debt()
        before = self.ledger.get_financial_overview()["family_net_worth_cents"]
        with self.assertRaises(ValueError):
            self.ledger.record_debt_repayment(source, debt["account_id"], 150000)
        self.assertEqual(self.ledger.get_account_balance_cents(source), 200000)
        self.ledger.record_debt_repayment(source, debt["account_id"], 50000)
        self.assertEqual(self.ledger.get_financial_overview()["family_net_worth_cents"], before)

    def test_void_repayment_and_opening_summary(self):
        source, debt = self.funded_debt()
        ident = self.ledger.record_debt_repayment(source, debt["account_id"], 10000)
        self.ledger.void_transaction(ident)
        summary = next(x for x in self.ledger.get_debts_summary()["debts"] if x["id"] == debt["account_id"])
        self.assertEqual(summary["debt_cents"], 100000)
        self.ledger.void_transaction(debt["transaction_id"])
        summary = next(x for x in self.ledger.get_debts_summary()["debts"] if x["id"] == debt["account_id"])
        self.assertEqual(summary["debt_cents"], 0)

    def test_partial_unique_replay_and_void_obligation(self):
        source, debt = self.funded_debt(monthly=10000)
        kwargs = {"source_account_id": source, "liability_account_id": debt["account_id"],
                  "amount_cents": 5000, "obligation_id": debt["obligation_id"], "idempotency_key": "repay-one"}
        first = self.ledger.record_debt_repayment(**kwargs)
        self.assertEqual(first, self.ledger.record_debt_repayment(**kwargs))
        obl = next(x for x in self.ledger.get_obligations() if x["id"] == debt["obligation_id"])
        self.assertEqual(obl["paid_amount_cents"], 5000)
        self.assertEqual(obl["remaining_cents"], 5000)
        kwargs["idempotency_key"] = "repay-two"
        second = self.ledger.record_debt_repayment(**kwargs)
        obl = next(x for x in self.ledger.get_obligations() if x["id"] == debt["obligation_id"])
        self.assertEqual(obl["paid_amount_cents"], 10000)
        self.assertTrue(obl["is_paid_this_month"])
        self.ledger.void_transaction(second)
        obl = next(x for x in self.ledger.get_obligations() if x["id"] == debt["obligation_id"])
        self.assertEqual(obl["remaining_cents"], 5000)

    def test_link_failure_rolls_back_whole_repayment(self):
        source, debt = self.funded_debt(monthly=10000)
        with patch.object(self.ledger, "mark_obligation_paid", side_effect=ValueError("injected failure")):
            with self.assertRaises(ValueError):
                self.ledger.record_debt_repayment(source, debt["account_id"], 5000, obligation_id=debt["obligation_id"])
        self.assertEqual(self.ledger.get_account_balance_cents(source), 200000)
        self.assertEqual(self.ledger.get_account_balance_cents(debt["account_id"]), 100000)

    def test_initial_debt_sync_contains_balanced_postings(self):
        _, debt = self.funded_debt()
        events = self.ledger._get_sync_engine().export_changes()["changes"]
        event = next(x for x in events if x["entity_id"] == debt["transaction_id"])
        postings = event["payload"]["postings"]
        self.assertEqual(sum(p["amount_cents"] for p in postings if p["posting_type"] == "DEBIT"),
                         sum(p["amount_cents"] for p in postings if p["posting_type"] == "CREDIT"))

    def test_full_payment_replay_does_not_become_overpayment(self):
        source, debt = self.funded_debt()
        first = self.ledger.record_debt_repayment(source, debt["account_id"], 100000, idempotency_key="full-payment")
        repeat = self.ledger.record_debt_repayment(source, debt["account_id"], 100000, idempotency_key="full-payment")
        self.assertEqual(first, repeat)
        self.assertEqual(self.ledger.get_account_balance_cents(debt["account_id"]), 0)
        self.assertEqual(self.ledger.get_account_balance_cents(source), 100000)

    def test_native_currency_excluded_from_ruble_totals(self):
        card = self.ledger.create_account("USD card", "LIABILITY", "CREDIT_CARD", "COMMON",
                    currency="USD", initial_balance_cents=10000)
        summary = self.ledger.get_debts_summary()
        row = next(x for x in summary["debts"] if x["id"] == card.id)
        self.assertEqual(row["currency"], "USD")
        self.assertEqual(row["debt_cents"], 10000)
        self.assertEqual(summary["total_debt_cents"], 0)
        self.assertEqual(summary["totals_by_currency"]["USD"]["total_debt_cents"], 10000)
        self.assertEqual(row["banking"]["status"], "UNSUPPORTED_CURRENCY")

    def test_failed_receive_creation_leaves_no_account(self):
        before = self.conn.execute("SELECT COUNT(*) FROM accounts").fetchone()[0]
        with self.assertRaises(ValueError):
            self.ledger.create_debt("Bad destination", receive_money=True,
                                   destination_account_id="missing", initial_debt_cents=10000)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM accounts").fetchone()[0], before)
