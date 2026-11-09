"""
Stage 18 Test: Debts Loading & Body Parser Robustness
Ensures:
1. `_read_json_body()` handles malformed JSON, empty payload, non-UTF8 bytes, non-dict JSON safely without raising unhandled exceptions or returning non-dicts.
2. `web_server.py` client-side `loadDebts()` script contains defensive checks for minSc, error alerts, and never leaves container frozen.
3. `calculate_credit_payoff_scenarios` handles 0 debt, custom payments, and returns complete dictionary structure.
"""
import unittest
import io
import json
from unittest.mock import MagicMock
from family_finances_os.web_server import FamilyFinancesHandler
from family_finances_os.ledger import LedgerEngine


class TestStage18DebtsLoadingRobustness(unittest.TestCase):
    def test_read_json_body_malformed_and_empty(self):
        """Test _read_json_body gracefully returns dict on corrupt or non-dict input."""
        test_cases = [
            (b"", 0, {}),
            (b"{bad json", 9, {}),
            (b"\xff\xfe\x00\x00", 4, {}),  # invalid utf-8
            (b"null", 4, {}),  # json null -> must return dict, not None
            (b"[\"item\"]", 8, {}),  # json list -> must return dict, not list
            (b"12345", 5, {}),  # json number -> must return dict
            (b"   ", 3, {}),  # whitespace only
            (b'{"key": "value"}', 16, {"key": "value"}),
        ]

        for payload, length, expected in test_cases:
            handler = FamilyFinancesHandler.__new__(FamilyFinancesHandler)
            handler.headers = {"Content-Length": str(length)}
            handler.rfile = io.BytesIO(payload)
            res = handler._read_json_body()
            self.assertIsInstance(res, dict, f"Failed for payload: {payload}")
            if expected:
                self.assertEqual(res, expected)

    def test_read_json_body_corrupted_header(self):
        """Test _read_json_body with invalid Content-Length headers."""
        for invalid_len in ["invalid", "-1", ""]:
            handler = FamilyFinancesHandler.__new__(FamilyFinancesHandler)
            handler.headers = {"Content-Length": invalid_len}
            handler.rfile = io.BytesIO(b"{}")
            res = handler._read_json_body()
            self.assertIsInstance(res, dict)
            self.assertEqual(res, {})

    def test_calculate_credit_payoff_scenarios_zero_debt(self):
        """Test payoff scenarios calculation when debt is zero."""
        sc = LedgerEngine.calculate_credit_payoff_scenarios(
            debt_cents=0,
            interest_rate_percent=24.8,
            min_payment_percent=3.0
        )
        self.assertIn("minimum_scenario", sc)
        self.assertIn("accelerated_scenarios", sc)
        self.assertEqual(sc["debt_cents"], 0)
        self.assertIsNotNone(sc["minimum_scenario"])
        self.assertEqual(sc["minimum_scenario"]["first_payment_rub"], "0.00")

    def test_calculate_credit_payoff_scenarios_positive_debt(self):
        """Test payoff scenarios calculation for standard debt."""
        sc = LedgerEngine.calculate_credit_payoff_scenarios(
            debt_cents=1000000,  # 10,000 rub
            interest_rate_percent=24.8,
            min_payment_percent=3.0,
            grace_period_days=120,
            grace_due_date="2026-12-01"
        )
        self.assertIsNotNone(sc["minimum_scenario"])
        self.assertIn("first_payment_rub", sc["minimum_scenario"])
        self.assertIn("days_to_payoff", sc["minimum_scenario"])
        self.assertTrue(len(sc["accelerated_scenarios"]) > 0)

    def test_client_side_load_debts_script_defenses(self):
        """Verify _render_app_html has defensive checks in loadDebts."""
        handler = FamilyFinancesHandler.__new__(FamilyFinancesHandler)
        html = handler._render_app_html()
        # 1. Check for minSc null check or defensive guard
        self.assertIn("const minSc = sc.minimum_scenario || null;", html)
        # 2. Check for container error notification on catch
        self.assertIn("Не удалось отобразить список задолженностей", html)
        # 3. Check for !res.ok check in loadDebts
        self.assertIn("if (!res.ok)", html)


if __name__ == "__main__":
    unittest.main()

