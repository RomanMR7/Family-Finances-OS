"""Financial invariant regressions; always use disposable explicit databases."""
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from family_finances_os.db import init_database, EncryptedDatabaseStorage
from family_finances_os.ledger import LedgerEngine, compute_tx_payload_hash
from family_finances_os.models import Posting, Transaction, generate_uuid, rubles_to_cents
from family_finances_os.importer import StatementImporter, clean_amount_str


class TestMathCore(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ffos_math_core_")
        self.path = Path(self.temp.name) / "source.db"
        init_database(self.path)
        self.ledger = LedgerEngine(self.path)
        self.ledger.seed_default_chart_of_accounts()
        self.ledger.seed_default_categories()

    def tearDown(self):
        self.temp.cleanup()

    def income(self, amount=10000, day="2026-11-11", key=None):
        ident=generate_uuid()
        tx=Transaction(ident,day,"INCOME","Audit income",postings=[
            Posting(generate_uuid(),ident,"acc_core_1010",amount,"DEBIT"),
            Posting(generate_uuid(),ident,"acc_core_4010",amount,"CREDIT")])
        return self.ledger.record_transaction(tx,key)

    def test_void_matches_overview_and_direct_balance(self):
        ident=self.income()
        self.ledger.void_transaction(ident)
        self.assertEqual(self.ledger.get_account_balance_cents("acc_core_1010"),0)
        overview=self.ledger.get_financial_overview()
        for field in ("common_liquid_assets_cents","family_net_worth_cents","common_safe_to_spend_cents"):
            self.assertEqual(overview[field],0)

    def test_split_edit_rejected_without_partial_header_write(self):
        ident=generate_uuid()
        tx=Transaction(ident,"2026-11-11","EXPENSE","split",postings=[
            Posting(generate_uuid(),ident,"acc_core_5010",600,"DEBIT"),
            Posting(generate_uuid(),ident,"acc_core_5020",400,"DEBIT"),
            Posting(generate_uuid(),ident,"acc_core_1010",1000,"CREDIT")])
        self.ledger.record_transaction(tx)
        with self.assertRaises(ValueError):
            self.ledger.update_transaction(ident,amount_cents=2000,description="must not persist")
        conn=self.ledger._get_conn()
        self.assertEqual(conn.execute("SELECT description FROM transactions WHERE id=?",(ident,)).fetchone()[0],"split")
        self.assertEqual(conn.execute("SELECT SUM(CASE posting_type WHEN 'DEBIT' THEN amount_cents ELSE -amount_cents END) FROM postings WHERE transaction_id=?",(ident,)).fetchone()[0],0)
        conn.close()

    def test_type_change_is_explicitly_rejected(self):
        ident=self.income()
        with self.assertRaises(ValueError): self.ledger.update_transaction(ident,tx_type="EXPENSE")
        self.assertEqual(self.ledger.get_account_balance_cents("acc_core_1010"),10000)

    def test_integer_cents_enforced(self):
        for amount in (1.5,True,float("nan"),float("inf"),-1,0):
            with self.subTest(amount=amount),self.assertRaises(ValueError):
                self.ledger.record_transfer("acc_core_1010","acc_core_1020",amount)

    def test_idempotent_date_mismatch_rejected(self):
        ident=self.income(key="same")
        self.assertEqual(self.income(key="same"),ident)
        with self.assertRaises(ValueError): self.income(day="2026-11-12",key="same")

    def test_legacy_hash_replay_still_validates_date(self):
        ident=self.income(key="legacy")
        conn=self.ledger._get_conn();conn.execute("UPDATE transactions SET payload_hash='legacy-hash' WHERE id=?",(ident,));conn.commit();conn.close()
        self.assertEqual(self.income(key="legacy"),ident)
        with self.assertRaises(ValueError): self.income(day="2026-11-12",key="legacy")

    def test_opening_replacement_keeps_history_and_converges(self):
        other_path=Path(self.temp.name)/"target.db";init_database(other_path)
        other=LedgerEngine(other_path);other.seed_default_chart_of_accounts()
        for amount in (10000,20000,0):
            self.ledger.set_initial_balance("acc_core_1010",amount)
            other._get_sync_engine().apply_remote_changes(self.ledger._get_sync_engine().export_changes(limit=10000))
            self.assertEqual(self.ledger.get_account_balance_cents("acc_core_1010"),amount)
            self.assertEqual(other.get_account_balance_cents("acc_core_1010"),amount)
        conn=self.ledger._get_conn()
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM transactions WHERE is_voided=1").fetchone()[0],2)
        conn.close()

    def test_new_account_opening_replicates(self):
        other_path=Path(self.temp.name)/"target.db";init_database(other_path)
        other=LedgerEngine(other_path);other.seed_default_chart_of_accounts()
        account=self.ledger.create_account("New","ASSET","CASH","COMMON",initial_balance_cents=12345)
        other._get_sync_engine().apply_remote_changes(self.ledger._get_sync_engine().export_changes(limit=10000))
        self.assertEqual(other.get_account_balance_cents(account.id),12345)

    def test_currency_units_are_never_added_to_rubles(self):
        self.ledger.set_initial_balance("acc_core_1010",10000)
        usd=self.ledger.create_account("USD","ASSET","CASH","COMMON",currency="USD",initial_balance_cents=10000)
        with self.assertRaises(ValueError): self.ledger.record_transfer("acc_core_1010",usd.id,100)
        overview=self.ledger.get_financial_overview()
        self.assertEqual(overview["common_liquid_assets_cents"],10000)
        self.assertEqual(overview["by_currency"]["USD"]["liquid_cents"],10000)
        self.assertEqual(overview["non_base_excluded"],["USD"])

    def test_nonzero_account_cannot_disappear_from_capital(self):
        self.ledger.set_initial_balance("acc_core_1010",10000)
        with self.assertRaises(ValueError): self.ledger.archive_account("acc_core_1010")
        self.assertEqual(self.ledger.get_financial_overview()["family_net_worth_cents"],10000)

    def test_import_identical_rows_accounts_and_replay(self):
        importer=StatementImporter(self.ledger)
        rows=importer.parse_csv("Date;Description;Amount\n2026-11-11;Coffee;-1.00\n2026-11-11;Coffee;-1.00")
        self.assertEqual(importer.commit_imported_items(rows,"acc_core_1010")["imported_count"],2)
        self.assertEqual(importer.commit_imported_items(rows,"acc_core_1010")["skipped_count"],2)
        self.assertEqual(importer.commit_imported_items(rows,"acc_core_1011")["imported_count"],2)

    def test_bank_id_survives_overlapping_statements(self):
        importer=StatementImporter(self.ledger)
        rows=importer.parse_csv("Date;Description;Amount;Transaction ID\n2026-11-11;Coffee;-1;bank1\n2026-11-11;Coffee;-1;bank2")
        self.assertEqual(importer.commit_imported_items(rows,"acc_core_1010")["imported_count"],2)
        other=importer.parse_csv("Date;Description;Amount;Transaction ID\n2026-11-11;Coffee;-1;bank2")
        self.assertEqual(importer.commit_imported_items(other,"acc_core_1010")["skipped_count"],1)

    def test_import_decimal_and_errors_are_explicit(self):
        self.assertEqual(clean_amount_str("1.005")[0],rubles_to_cents("1.005"))
        importer=StatementImporter(self.ledger)
        rows=importer.parse_csv("Date;Description;Amount\n2026-11-11;Coffee;-1")
        rows[0]["amount_cents"]=1.5
        result=importer.commit_imported_items(rows,"acc_core_1010")
        self.assertEqual(result["status"],"partial")
        self.assertEqual(result["error_count"],1)
        self.assertEqual(result["skipped_count"],0)

    def test_legacy_rounding_key_does_not_duplicate_old_import(self):
        import hashlib
        legacy_key="imp_"+hashlib.sha256("2026-11-11:100:EXPENSE:coffee".encode()).hexdigest()[:16]
        ident=generate_uuid()
        self.ledger.record_transaction(Transaction(ident,"2026-11-11","EXPENSE","Coffee",postings=[
            Posting(generate_uuid(),ident,"acc_core_5010",100,"DEBIT"),Posting(generate_uuid(),ident,"acc_core_1010",100,"CREDIT")]),legacy_key)
        importer=StatementImporter(self.ledger)
        rows=importer.parse_csv("Date;Description;Amount\n2026-11-11;Coffee;-1.005")
        result=importer.commit_imported_items(rows,"acc_core_1010")
        self.assertEqual(result["imported_count"],0)
        self.assertEqual(result["error_count"],1)
        self.assertEqual(self.ledger.get_account_balance_cents("acc_core_1010"),-100)

    def test_partial_obligation_accumulates_unique_transactions_and_void(self):
        obligation=self.ledger.create_obligation("Debt bill",10000,15)
        debt=self.ledger.create_account("Debt","LIABILITY","LOAN","COMMON",initial_balance_cents=10000)
        def payment(amount):
            ident=generate_uuid(); self.ledger.record_transaction(Transaction(ident,"2026-11-11","CREDIT_PAYMENT","payment",postings=[
                Posting(generate_uuid(),ident,debt.id,amount,"DEBIT"),Posting(generate_uuid(),ident,"acc_core_1010",amount,"CREDIT")]))
            return ident
        first=payment(3000)
        self.ledger.mark_obligation_paid(obligation.id,"2026-11",first,3000)
        self.ledger.mark_obligation_paid(obligation.id,"2026-11",first,3000)
        self.assertEqual(self.ledger.calculate_unpaid_obligations_cents("2026-11"),(7000,10000,3000))
        second=payment(7000);self.ledger.mark_obligation_paid(obligation.id,"2026-11",second,7000)
        self.assertEqual(self.ledger.calculate_unpaid_obligations_cents("2026-11"),(0,10000,10000))
        self.ledger.void_transaction(first)
        self.assertEqual(self.ledger.calculate_unpaid_obligations_cents("2026-11"),(3000,10000,7000))

    def test_invalid_month_and_amount_do_not_create_payment(self):
        obligation=self.ledger.create_obligation("Bill",10000,15)
        for month,amount in (("2026-13",100),("2026-11",-100),("2026-11",0)):
            with self.assertRaises(ValueError): self.ledger.mark_obligation_paid(obligation.id,month,paid_amount_cents=amount)
        self.assertEqual(self.ledger.calculate_unpaid_obligations_cents("2026-11"),(10000,10000,0))

    def test_manual_paid_is_status_only_and_unmark_restores_remaining(self):
        obligation=self.ledger.create_obligation("Bill",10000,15)
        self.ledger.mark_obligation_paid(obligation.id,"2026-11")
        self.assertEqual(self.ledger.calculate_unpaid_obligations_cents("2026-11"),(0,10000,10000))
        self.assertEqual(self.ledger.get_account_balance_cents("acc_core_1010"),0)
        self.ledger.unmark_obligation_paid(obligation.id,"2026-11")
        self.assertEqual(self.ledger.calculate_unpaid_obligations_cents("2026-11"),(10000,10000,0))

    def test_composed_command_failure_does_not_commit_money(self):
        self.ledger.set_initial_balance("acc_core_1010",10000)
        with self.assertRaises(RuntimeError):
            with self.ledger.atomic():
                self.ledger.record_transfer("acc_core_1010","acc_core_1020",3000)
                raise RuntimeError("injected after nested transfer")
        self.assertEqual(self.ledger.get_account_balance_cents("acc_core_1010"),10000)
        self.assertEqual(self.ledger.get_account_balance_cents("acc_core_1020"),0)
        self.ledger.create_category("Unrelated commit","EXPENSE")
        self.assertEqual(self.ledger.get_account_balance_cents("acc_core_1020"),0)

    def test_edit_snapshot_replicates_full_balanced_postings(self):
        other_path=Path(self.temp.name)/"target.db";init_database(other_path)
        other=LedgerEngine(other_path);other.seed_default_chart_of_accounts()
        ident=self.income(1000)
        other._get_sync_engine().apply_remote_changes(self.ledger._get_sync_engine().export_changes(limit=10000))
        self.ledger.update_transaction(ident,amount_cents=2000)
        other._get_sync_engine().apply_remote_changes(self.ledger._get_sync_engine().export_changes(limit=10000))
        self.assertEqual(other.get_account_balance_cents("acc_core_1010"),2000)

    def test_paid_obligation_rename_and_unmark_replicate(self):
        other_path=Path(self.temp.name)/"target.db";init_database(other_path)
        other=LedgerEngine(other_path);other.seed_default_chart_of_accounts()
        obligation=self.ledger.create_obligation("Bill",10000,15)
        self.ledger.mark_obligation_paid(obligation.id,"2026-11",paid_amount_cents=3000)
        self.ledger.update_obligation(obligation.id,name="Renamed bill")
        other._get_sync_engine().apply_remote_changes(self.ledger._get_sync_engine().export_changes(limit=10000))
        self.assertEqual(other.calculate_unpaid_obligations_cents("2026-11"),(7000,10000,3000))
        self.ledger.unmark_obligation_paid(obligation.id,"2026-11")
        other._get_sync_engine().apply_remote_changes(self.ledger._get_sync_engine().export_changes(limit=10000))
        self.assertEqual(other.calculate_unpaid_obligations_cents("2026-11"),(10000,10000,0))

    def test_encrypted_write_failure_rolls_back_pending_command(self):
        storage=EncryptedDatabaseStorage(Path(self.temp.name)/"encrypted.db.enc")
        storage.initialize_new("AuditOnly!2026")
        try:
            with patch("family_finances_os.db.GLOBAL_STORAGE",storage):
                ledger=LedgerEngine(storage.get_connection())
                ledger.seed_default_chart_of_accounts()
                ledger.set_initial_balance("acc_core_1010",10000)
                before=storage.enc_path.read_bytes()
                with patch.object(storage,"_write_container_atomically",side_effect=OSError("injected disk failure")):
                    with self.assertRaises(OSError):
                        ledger.record_transfer("acc_core_1010","acc_core_1020",3000)
                self.assertEqual(storage.enc_path.read_bytes(),before)
                self.assertEqual(ledger.get_account_balance_cents("acc_core_1010"),10000)
                self.assertEqual(ledger.get_account_balance_cents("acc_core_1020"),0)
        finally:
            storage.lock()


if __name__ == "__main__":
    unittest.main()
