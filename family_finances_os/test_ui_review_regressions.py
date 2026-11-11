"""Regressions confirmed by browser QA; real ledger and HTTP handler, isolated DB."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from family_finances_os.db import EncryptedDatabaseStorage
from family_finances_os.ledger import LedgerEngine
from family_finances_os.test_stage5_e2e import MockSocket
from family_finances_os.web_server import FamilyFinancesHandler, GLOBAL_SESSION_MANAGER


class TestUIReviewRegressions(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='ffos_ui_regression_')
        self.storage = EncryptedDatabaseStorage(enc_path=Path(self.directory.name) / 'review.db.enc')
        connection = self.storage.initialize_new('IsolatedReviewTest!')
        self.ledger = LedgerEngine(conn_or_path=connection)
        self.ledger.seed_default_chart_of_accounts()
        self.original_storage = FamilyFinancesHandler.storage
        FamilyFinancesHandler.storage = self.storage
        self.token = GLOBAL_SESSION_MANAGER.create_session({'user_id':'review-test','role':'OWNER'})

    def tearDown(self):
        FamilyFinancesHandler.storage = self.original_storage
        self.storage.lock()
        self.directory.cleanup()

    def get(self, route):
        request = (f'GET {route} HTTP/1.1\r\nHost: 127.0.0.1\r\n'
                   f'Authorization: Bearer {self.token}\r\n\r\n').encode()
        socket = MockSocket(request)
        FamilyFinancesHandler(socket, ('127.0.0.1',12345), None)
        response = bytes(socket.output)
        self.assertIn(b'200 OK', response.split(b'\r\n',1)[0])
        return json.loads(response.split(b'\r\n\r\n',1)[1])

    def test_obligation_summary_maps_paid_total_unpaid_and_month(self):
        rent = self.ledger.create_obligation('Rent',100000,5)
        self.ledger.create_obligation('Internet',25000,15)
        self.ledger.mark_obligation_paid(rent.id,'2026-11')
        november = self.get('/api/obligations?month=2026-11')
        self.assertEqual((november['total_rub'],november['paid_rub'],november['unpaid_rub']),
                         ('1250.00','1000.00','250.00'))
        october = self.get('/api/obligations?month=2026-10')
        self.assertEqual((october['total_rub'],october['paid_rub'],october['unpaid_rub']),
                         ('1250.00','0.00','1250.00'))

    def test_overview_retains_native_currency_and_exact_minor_units(self):
        account = self.ledger.create_account('USD savings','ASSET','SAVINGS','COMMON',
                                             initial_balance_cents=1234567,currency='USD')
        # The overview route uses the global ledger factory; bind it to this isolated real ledger.
        with patch('family_finances_os.web_server.LedgerEngine', return_value=self.ledger):
            returned = next(a for a in self.get('/api/overview')['accounts'] if a['id']==account.id)
        self.assertEqual(returned['currency'],'USD')
        self.assertEqual(returned['balance_cents'],1234567)
        self.assertEqual(returned['balance_rub'],'12345.67')


if __name__ == '__main__':
    unittest.main()
