"""Economic conservation across offline peers, replay and linked reversals."""
import json
import sqlite3
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from datetime import date
from contextlib import closing
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from family_finances_os.db import init_database
from family_finances_os.ledger import LedgerEngine
from family_finances_os.models import Posting, Transaction, generate_uuid, rubles_to_cents
from family_finances_os.sync import P2PSyncEngine


class TestOfflineConservation(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ffos_convergence_')
        self.path = Path(self.temp.name)/'source.db'
        init_database(self.path)
        self.l = LedgerEngine(self.path)
        self.l.seed_default_chart_of_accounts()
        self.l.seed_default_categories()
        self.l.set_initial_balance('acc_core_1010', 100000)

    def tearDown(self):
        self.temp.cleanup()

    def clone(self):
        target = Path(self.temp.name)/'peer.db'
        source = self.l._get_conn()
        try:
            with closing(sqlite3.connect(target)) as dest:
                source.backup(dest)
        finally:
            self.l._close_if_local(source)
        peer = LedgerEngine(target)
        peer._sync_engine = P2PSyncEngine(target, device_id='independent-peer')
        return peer

    def exchange(self, peer):
        a, b = self.l._get_sync_engine(), peer._get_sync_engine()
        # Capture both packets before delivering either, then replay both.
        left, right = a.export_changes(limit=10000), b.export_changes(limit=10000)
        for _ in range(2):
            a.apply_remote_changes(right)
            b.apply_remote_changes(left)

    def expense(self, ledger, amount):
        ident = generate_uuid()
        ledger.record_transaction(Transaction(ident, '2026-11-11', 'EXPENSE', 'Bill', postings=[
            Posting(generate_uuid(), ident, 'acc_core_5010', amount, 'DEBIT'),
            Posting(generate_uuid(), ident, 'acc_core_1010', amount, 'CREDIT')]))
        return ident

    def test_independent_goal_deposits_conserve_money_and_tracking(self):
        goal = self.l.create_goal('Goal', 100000, account_id='acc_core_1030', initial_saved_cents=1000)
        peer = self.clone()
        self.l.contribute_to_goal(goal.id, 10000, 'acc_core_1010', idempotency_key='A')
        peer.contribute_to_goal(goal.id, 20000, 'acc_core_1010', idempotency_key='B')
        self.exchange(peer)
        for ledger in (self.l, peer):
            self.assertEqual(ledger.get_goals()[0]['current_amount_cents'], 31000)
            self.assertEqual(ledger.get_account_balance_cents('acc_core_1030'), 30000)
            self.assertEqual(ledger.get_account_balance_cents('acc_core_1010'), 70000)

    def test_same_goal_command_on_two_peers_is_one_transfer(self):
        goal = self.l.create_goal('Goal', 100000, account_id='acc_core_1030')
        peer = self.clone()
        for ledger in (self.l, peer):
            ledger.contribute_to_goal(goal.id, 10000, 'acc_core_1010', idempotency_key='same-command')
        self.exchange(peer)
        for ledger in (self.l, peer):
            self.assertEqual(ledger.get_goals()[0]['current_amount_cents'], 10000)
            self.assertEqual(ledger.get_account_balance_cents('acc_core_1030'), 10000)

    def test_envelope_history_survives_concurrent_deposits_and_linked_void(self):
        env = self.l.create_envelope('Envelope', initial_amount_cents=500, linked_account_id='acc_core_1030')
        peer = self.clone()
        result = self.l.deposit_to_envelope(env.id, 10000, 'acc_core_1010', idempotency_key='env-A')
        peer.deposit_to_envelope(env.id, 20000, 'acc_core_1010', idempotency_key='env-B')
        self.exchange(peer)
        self.assertEqual(self.l.get_envelope(env.id)['current_amount_cents'], 30500)
        self.l.void_transaction(result['transaction_id'])
        self.exchange(peer)
        for ledger in (self.l, peer):
            self.assertEqual(ledger.get_envelope(env.id)['current_amount_cents'], 20500)
            self.assertEqual(ledger.get_account_balance_cents('acc_core_1030'), 20000)

    def test_independent_partial_payments_sum_and_void_reduces_remainder(self):
        obligation = self.l.create_obligation('Bill', 10000, 15)
        peer = self.clone()
        first = self.expense(self.l, 3000)
        second = self.expense(peer, 4000)
        self.l.mark_obligation_paid(obligation.id, '2026-11', first, 3000)
        peer.mark_obligation_paid(obligation.id, '2026-11', second, 4000)
        self.exchange(peer)
        for ledger in (self.l, peer):
            self.assertEqual(ledger.get_obligations('2026-11')[0]['remaining_cents'], 3000)
        self.l.void_transaction(first)
        self.exchange(peer)
        for ledger in (self.l, peer):
            self.assertEqual(ledger.get_obligations('2026-11')[0]['remaining_cents'], 6000)

    def test_unmark_tombstone_blocks_delayed_payment_resurrection(self):
        obligation = self.l.create_obligation('Bill', 10000, 15)
        first = self.expense(self.l, 3000)
        self.l.mark_obligation_paid(obligation.id, '2026-11', first, 3000)
        peer = self.clone()
        old = peer._get_sync_engine().export_changes(limit=10000)
        self.l.unmark_obligation_paid(obligation.id, '2026-11')
        self.l._get_sync_engine().apply_remote_changes(old)
        self.exchange(peer)
        for ledger in (self.l, peer):
            self.assertEqual(ledger.get_obligations('2026-11')[0]['paid_amount_cents'], 0)

    def test_distinct_engine_clocks_do_not_lose_a_page(self):
        with patch('family_finances_os.sync.current_epoch_ms', return_value=1900000000000):
            a = P2PSyncEngine(self.path)
            b = P2PSyncEngine(self.path)
            a.record_change_event('ACCOUNT', 'acc_core_1010', 'UPDATE', {'name': 'First'})
            first = a.export_changes(limit=10000)['next_cursor']
            b.record_change_event('ACCOUNT', 'acc_core_1020', 'UPDATE', {'name': 'Second'})
            remaining = a.export_changes(since_hlc=first)
            self.assertEqual(len(remaining['changes']), 1)
            self.assertEqual(remaining['changes'][0]['payload']['name'], 'Second')

    def test_forecast_does_not_add_foreign_currency_to_rubles(self):
        usd = self.l.create_account('USD', 'ASSET', 'CHECKING', 'COMMON', currency='USD', initial_balance_cents=10000)
        self.l.create_obligation('Dollar bill', 10000, 11, payment_account_id=usd.id)
        from family_finances_os.reporting import forecast
        result = forecast(self.l, 7, False, today=date(2026, 11, 11))
        self.assertEqual(result['day_zero_balance_cents'], 100000)

    def test_foreign_expense_cannot_mark_a_ruble_bill_paid(self):
        usd = self.l.create_account('USD', 'ASSET', 'CHECKING', 'COMMON', currency='USD')
        obligation = self.l.create_obligation('RUB bill', 10000, 15)
        ident = generate_uuid()
        self.l.record_transaction(Transaction(ident, '2026-11-11', 'EXPENSE', 'USD expense', postings=[
            Posting(generate_uuid(), ident, 'acc_core_5010', 10000, 'DEBIT'),
            Posting(generate_uuid(), ident, usd.id, 10000, 'CREDIT')]))
        with self.assertRaises(ValueError):
            self.l.mark_obligation_paid(obligation.id, '2026-11', ident, 10000)
        self.assertEqual(self.l.get_obligations('2026-11')[0]['remaining_cents'], 10000)

    def test_decimal_conversion_rejects_invalid_nonempty_values(self):
        for raw in ('NaN', 'Infinity', '-Infinity', 'bad', True, float('nan')):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                rubles_to_cents(raw)
        self.assertEqual(rubles_to_cents('1,005'), 101)
        self.assertEqual(rubles_to_cents('-1,005'), -101)

    def test_legacy_amount_snapshot_cannot_overwrite_event_tracking(self):
        goal = self.l.create_goal('Goal', 100000)
        peer = self.clone()
        s = self.l._get_sync_engine()
        legacy = {'entity_name': 'GOAL', 'entity_id': goal.id, 'change_type': 'UPDATE',
                  'device_id': 'old-client', 'hlc_timestamp': s.hlc.now(),
                  'payload': {'current_amount_cents': 5000}}
        with self.assertRaisesRegex(ValueError, 'Обновите оба устройства'):
            peer._get_sync_engine().apply_remote_changes({'changes': [legacy]})
        self.assertEqual(peer.get_goals()[0]['current_amount_cents'], 0)


class TestPublicHostedBoundary(unittest.TestCase):
    def test_real_http_health_landing_and_finance_refusal(self):
        import ast
        import importlib.util
        entry = Path(__file__).resolve().parents[1]/'api'/'index.py'
        definitions = ast.parse(entry.read_text(encoding='utf-8')).body
        self.assertTrue(any(isinstance(node, ast.ClassDef) and node.name == 'handler' for node in definitions))
        spec = importlib.util.spec_from_file_location('ffos_vercel_entry', entry)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        server = ThreadingHTTPServer(('127.0.0.1', 0), module.handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        url = f'http://127.0.0.1:{server.server_port}'
        try:
            with urllib.request.urlopen(url + '/') as response:
                self.assertIn('страница проекта', response.read().decode('utf-8'))
            with urllib.request.urlopen(url + '/api/index.py?__url=/api/health') as response:
                self.assertFalse(json.load(response)['finance_api_enabled'])
            with self.assertRaises(urllib.error.HTTPError) as caught:
                urllib.request.urlopen(urllib.request.Request(url + '/api/unlock', data=b'{}'))
            self.assertEqual(caught.exception.code, 503)
            caught.exception.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
