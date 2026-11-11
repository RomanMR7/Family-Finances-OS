"""Reservation command invariants; run through the isolated regression runner."""
import sqlite3
import tempfile
import unittest
from pathlib import Path
from datetime import date,timedelta

from family_finances_os.db import init_database,get_connection
from family_finances_os.ledger import LedgerEngine
from family_finances_os.sync import P2PSyncEngine


class TestReservationMath(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix="ffos_reservation_fix_")
        self.path=Path(self.temp.name)/"ledger.db"
        init_database(self.path)
        self.conn=get_connection(self.path)
        self.ledger=LedgerEngine(self.conn)
        self.ledger.seed_default_chart_of_accounts()
        self.ledger.seed_default_categories()
        self.cash="acc_core_1010";self.reserve="acc_core_1030"
        self.ledger.set_initial_balance(self.cash,100000)

    def tearDown(self):
        self.conn.close();self.temp.cleanup()

    def scalar(self,query,args=()):
        return self.conn.execute(query,args).fetchone()[0]

    def test_goal_command_idempotency_covers_money_and_tracking(self):
        goal=self.ledger.create_goal("Goal",50000,account_id=self.reserve)
        first=self.ledger.contribute_to_goal(goal.id,25000,self.cash,idempotency_key="same")
        second=self.ledger.contribute_to_goal(goal.id,25000,self.cash,idempotency_key="same")
        self.assertEqual(first,second)
        self.assertEqual(self.ledger.get_account_balance_cents(self.cash),75000)
        self.assertEqual(self.ledger.get_account_balance_cents(self.reserve),25000)
        self.assertEqual(self.ledger.get_goals()[0]["current_amount_cents"],25000)
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM goal_contributions"),1)
        with self.assertRaises(ValueError):
            self.ledger.contribute_to_goal(goal.id,25001,self.cash,idempotency_key="same")

    def test_goal_idempotency_without_bank_transfer_and_after_reopen(self):
        goal=self.ledger.create_goal("Virtual",10000)
        self.ledger.contribute_to_goal(goal.id,1000,idempotency_key="virtual")
        reopened=LedgerEngine(self.path)
        reopened.contribute_to_goal(goal.id,1000,idempotency_key="virtual")
        self.assertEqual(reopened.get_goals()[0]["current_amount_cents"],1000)
        self.assertEqual(self.ledger.get_account_balance_cents(self.cash),100000)

    def test_goal_idempotency_same_account(self):
        goal=self.ledger.create_goal("Same",10000,account_id=self.cash)
        for _ in range(2):
            self.ledger.contribute_to_goal(goal.id,1000,self.cash,idempotency_key="same-account")
        self.assertEqual(self.ledger.get_goals()[0]["current_amount_cents"],1000)
        self.assertEqual(self.ledger.get_account_balance_cents(self.cash),100000)

    def test_goal_failure_rolls_back_bank_snapshot_history_and_cdc(self):
        goal=self.ledger.create_goal("Fault",50000,account_id=self.reserve)
        prior=self.scalar("SELECT COUNT(*) FROM change_log")
        self.conn.execute("CREATE TRIGGER fail_contribution BEFORE INSERT ON goal_contributions BEGIN SELECT RAISE(ABORT,'injected'); END")
        with self.assertRaises(sqlite3.IntegrityError):
            self.ledger.contribute_to_goal(goal.id,25000,self.cash,idempotency_key="failure")
        self.ledger.create_category("Unrelated","EXPENSE")
        self.assertEqual(self.ledger.get_account_balance_cents(self.cash),100000)
        self.assertEqual(self.ledger.get_account_balance_cents(self.reserve),0)
        self.assertEqual(self.ledger.get_goals()[0]["current_amount_cents"],0)
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM goal_contributions"),0)
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM change_log"),prior+1)

    def test_goal_completed_snapshot_and_archive_are_full(self):
        goal=self.ledger.create_goal("Complete",10000,initial_saved_cents=5000)
        self.ledger.update_goal(goal.id,target_amount_cents=4000)
        payload=self.ledger._get_sync_engine().export_changes()["changes"][-1]["payload"]
        self.assertEqual(payload["is_completed"],1)
        self.assertEqual(payload["name"],"Complete")
        self.ledger.archive_goal(goal.id)
        archived=self.ledger._get_sync_engine().export_changes()["changes"][-1]["payload"]
        self.assertEqual(archived["is_active"],0)
        self.assertEqual(archived["target_amount_cents"],4000)

    def test_envelope_invalid_source_cannot_commit_phantom_balance(self):
        env=self.ledger.create_envelope("Invalid")
        with self.assertRaises(ValueError):
            self.ledger.deposit_to_envelope(env.id,20000,source_account_id="missing")
        self.ledger.create_category("Other","EXPENSE")
        self.assertFalse(self.conn.in_transaction)
        self.assertEqual(self.ledger.get_envelope(env.id)["current_amount_cents"],0)
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM envelope_operations"),0)

    def test_path_mode_linked_envelope_no_self_lock_and_cash_conservation(self):
        path_ledger=LedgerEngine(self.path)
        env=path_ledger.create_envelope("Path",linked_account_id=self.reserve)
        path_ledger.deposit_to_envelope(env.id,30000,self.cash)
        path_ledger.withdraw_from_envelope(env.id,10000,self.cash)
        self.assertEqual(path_ledger.get_account_balance_cents(self.cash),80000)
        self.assertEqual(path_ledger.get_account_balance_cents(self.reserve),20000)
        self.assertEqual(path_ledger.get_envelope(env.id)["current_amount_cents"],20000)
        self.assertEqual(path_ledger.get_spending_analytics("all")["total_expense_cents"],0)

    def test_envelope_failure_after_bank_transfer_rolls_back_everything(self):
        env=self.ledger.create_envelope("Fault",linked_account_id=self.reserve)
        # The command-result cache is written after the real bank transfer.
        self.conn.execute("CREATE TRIGGER fail_envelope_result BEFORE INSERT ON system_meta WHEN NEW.key LIKE 'reservation-command-v1:%' BEGIN SELECT RAISE(ABORT,'injected'); END")
        with self.assertRaises(sqlite3.IntegrityError):
            self.ledger.deposit_to_envelope(env.id,20000,self.cash,idempotency_key="fail-after-bank")
        self.ledger.create_category("Later","EXPENSE")
        self.assertEqual(self.ledger.get_envelope(env.id)["current_amount_cents"],0)
        self.assertEqual(self.ledger.get_account_balance_cents(self.cash),100000)
        self.assertEqual(self.ledger.get_account_balance_cents(self.reserve),0)

    def test_envelope_request_idempotency_and_conservation(self):
        first=self.ledger.create_envelope("First",initial_amount_cents=5000)
        second=self.ledger.create_envelope("Second")
        for _ in range(2):
            self.ledger.deposit_to_envelope(first.id,2000,idempotency_key="deposit")
            self.ledger.withdraw_from_envelope(first.id,1000,idempotency_key="withdraw")
            self.ledger.transfer_between_envelopes(first.id,second.id,1000,idempotency_key="move")
        values={e["id"]:e["current_amount_cents"] for e in self.ledger.get_envelopes()}
        self.assertEqual(values,{first.id:5000,second.id:1000})
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM envelope_operations"),4)
        with self.assertRaises(ValueError):
            self.ledger.deposit_to_envelope(first.id,2001,idempotency_key="deposit")

    def test_history_cdc_includes_initial_adjustment_deposit_withdraw_transfer(self):
        first=self.ledger.create_envelope("First",initial_amount_cents=5000)
        second=self.ledger.create_envelope("Second")
        self.ledger.update_envelope(first.id,current_amount_cents=6000)
        self.ledger.deposit_to_envelope(first.id,2000)
        self.ledger.withdraw_from_envelope(first.id,1000)
        self.ledger.transfer_between_envelopes(first.id,second.id,1000)
        events=self.ledger._get_sync_engine().export_changes()["changes"]
        ops=[e for e in events if e["entity_name"]=="ENVELOPE_OPERATION"]
        self.assertEqual(len(ops),5)
        self.assertEqual(len({e["entity_id"] for e in ops}),5)
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM envelope_operations"),5)

    def test_cross_linked_transfer_and_non_rub_tracking_rejected(self):
        first=self.ledger.create_envelope("First",initial_amount_cents=1000,linked_account_id=self.cash)
        second=self.ledger.create_envelope("Second",linked_account_id=self.reserve)
        with self.assertRaises(ValueError):
            self.ledger.transfer_between_envelopes(first.id,second.id,100)
        usd=self.ledger.create_account("USD","ASSET","SAVINGS","COMMON",currency="USD")
        with self.assertRaises(ValueError):self.ledger.create_goal("USD goal",1000,account_id=usd.id)
        with self.assertRaises(ValueError):self.ledger.create_envelope("USD env",linked_account_id=usd.id)

    def test_exact_cents_and_monthly_ceiling(self):
        with self.assertRaises(ValueError):self.ledger.create_envelope("Fraction",initial_amount_cents=1.5)
        with self.assertRaises(ValueError):self.ledger.create_goal("Bool",True)
        due=(date.today()+timedelta(days=60)).isoformat()
        self.ledger.create_goal("Pace",101,target_date=due)
        goal=self.ledger.get_goals()[0]
        self.assertEqual(goal["recommended_monthly_rub"],"0.51")
        self.assertTrue(goal["recommendation_is_estimate"])

    def test_goals_and_history_round_trip_without_duplicate_or_cascade(self):
        goal=self.ledger.create_goal("Sync",10000)
        self.ledger.contribute_to_goal(goal.id,2000,idempotency_key="sync")
        self.ledger.update_goal(goal.id,name="Renamed")
        env=self.ledger.create_envelope("Envelope",initial_amount_cents=5000)
        self.ledger.deposit_to_envelope(env.id,2000)
        self.ledger.withdraw_from_envelope(env.id,1000)
        self.ledger.update_envelope(env.id,name="Renamed env")
        target=Path(self.temp.name)/"peer.db";init_database(target)
        peer=LedgerEngine(target);peer.seed_default_chart_of_accounts();peer.seed_default_categories()
        sync=P2PSyncEngine(target);batch=self.ledger._get_sync_engine().export_changes()
        sync.apply_remote_changes(batch);sync.apply_remote_changes(batch)
        self.assertEqual(peer.get_goals()[0]["current_amount_cents"],2000)
        self.assertEqual(peer.get_goals()[0]["name"],"Renamed")
        self.assertEqual(peer.get_envelope(env.id)["current_amount_cents"],6000)
        peerconn=get_connection(target)
        try:
            self.assertEqual(peerconn.execute("SELECT COUNT(*) FROM goal_contributions").fetchone()[0],1)
            self.assertEqual(peerconn.execute("SELECT COUNT(*) FROM envelope_operations").fetchone()[0],3)
        finally:peerconn.close()

    def test_command_retry_on_second_peer_does_not_repeat_goal_or_envelope(self):
        goal=self.ledger.create_goal("Goal",50000,account_id=self.reserve)
        self.ledger.contribute_to_goal(goal.id,10000,self.cash,idempotency_key="peer-goal")
        env=self.ledger.create_envelope("Envelope",linked_account_id=self.reserve)
        first=self.ledger.deposit_to_envelope(env.id,20000,self.cash,idempotency_key="peer-deposit")
        target=Path(self.temp.name)/"retry-peer.db";init_database(target)
        peer=LedgerEngine(target);peer.seed_default_chart_of_accounts();peer.seed_default_categories()
        P2PSyncEngine(target).apply_remote_changes(self.ledger._get_sync_engine().export_changes())
        peer.contribute_to_goal(goal.id,10000,self.cash,idempotency_key="peer-goal")
        retry=peer.deposit_to_envelope(env.id,20000,self.cash,idempotency_key="peer-deposit")
        self.assertEqual(retry["transaction_id"],first["transaction_id"])
        self.assertEqual(peer.get_account_balance_cents(self.cash),70000)
        self.assertEqual(peer.get_account_balance_cents(self.reserve),30000)
        self.assertEqual(peer.get_envelope(env.id)["current_amount_cents"],20000)
        self.assertEqual(peer.get_goals()[0]["current_amount_cents"],10000)
        with self.assertRaises(ValueError):
            peer.deposit_to_envelope(env.id,20001,self.cash,idempotency_key="peer-deposit")


if __name__=="__main__":
    unittest.main()
