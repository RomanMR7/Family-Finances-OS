"""Independent economic expectations for reporting and offline merge."""
import copy
import tempfile
import unittest
from datetime import date
from pathlib import Path

from family_finances_os.db import init_database
from family_finances_os.ledger import LedgerEngine
from family_finances_os.models import Transaction, Posting, generate_uuid
from family_finances_os.reporting import analytics, forecast


class TestMathReportingSync(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='ffos_reporting_sync_')
        self.l=self.ledger('source');self.r=self.ledger('remote')
        self.today=date(2026,11,11)

    def tearDown(self):self.temp.cleanup()

    def ledger(self,name):
        p=Path(self.temp.name)/(name+'.db');init_database(p)
        l=LedgerEngine(p);l.seed_default_chart_of_accounts();l.seed_default_categories();return l

    def tx(self,amount,when,kind='EXPENSE'):
        ident=generate_uuid();cash='acc_core_1010'
        counterpart='acc_core_4010' if kind=='INCOME' else 'acc_core_5010'
        debit,credit=(cash,counterpart) if kind in ('INCOME','REFUND') else (counterpart,cash)
        self.l.record_transaction(Transaction(ident,when,kind,'Audit',postings=[
            Posting(generate_uuid(),ident,debit,amount,'DEBIT'),Posting(generate_uuid(),ident,credit,amount,'CREDIT')]))
        return ident

    def test_exact_calendar_window_and_refund_conservation(self):
        self.tx(100000,'2026-11-01','INCOME');self.tx(10000,'2026-11-02');self.tx(3000,'2026-11-03','REFUND');self.tx(9000,'2026-10-12')
        a=analytics(self.l,'30d',today=self.today)
        self.assertEqual((a['days_count'],a['total_expense_cents'],a['net_savings_cents']),(30,7000,93000))
        self.assertEqual(analytics(self.l,'90d',today=self.today)['days_count'],90)
        with self.assertRaises(ValueError):analytics(self.l,start_date='2026-11-11',end_date='2026-11-01',today=self.today)

    def test_all_time_average_starts_at_real_history(self):
        self.tx(3100,'2026-10-12')
        a=analytics(self.l,'all',today=self.today)
        self.assertEqual((a['days_count'],a['daily_avg_expense_cents']),(31,100))

    def test_paid_future_month_and_day_zero_and_soft_gap(self):
        self.l.set_initial_balance('acc_core_1010',100000)
        due=self.l.create_obligation('Due today',10000,11)
        future=self.l.create_obligation('Prepaid',20000,1)
        self.l.mark_obligation_paid(future.id,'2026-11')
        self.l.mark_obligation_paid(future.id,'2026-12')
        f=forecast(self.l,30,False,safety_buffer_cents=95000,today=self.today)
        self.assertEqual(f['day_zero_balance_cents'],90000)
        self.assertEqual(f['timeline'][-1]['balance_cents'],80000) # Next month's due11, not prepaid due1.
        self.assertEqual(f['first_soft_gap_date'],'2026-11-11')
        self.assertTrue(f['has_soft_gap'])
        self.l.mark_obligation_paid(due.id,'2026-12')
        f=forecast(self.l,30,False,today=self.today)
        self.assertEqual(f['timeline'][-1]['balance_cents'],90000)

    def test_existing_deficit_is_today(self):
        self.l.create_account('Debt','LIABILITY','CREDIT_CARD','COMMON',initial_balance_cents=50000)
        f=forecast(self.l,7,False,today=self.today)
        self.assertEqual(f['first_deficit_date'],'2026-11-11')
        self.assertEqual(f['first_deficit_cents'],50000)

    def test_transfer_days_do_not_change_burn_readiness(self):
        self.l.set_initial_balance('acc_core_1010',100000)
        self.tx(3000,'2026-11-11')
        for when in ('2026-11-01','2026-11-02'):self.l.record_transfer('acc_core_1010','acc_core_1020',1,tx_date=when)
        self.assertEqual(forecast(self.l,7,today=self.today)['daily_burn_cents'],0)

    def batch(self,events):
        s=self.l._get_sync_engine()
        return {'sender_device_id':s.device_id,'current_hlc':s.hlc.now(),'changes':events}

    def test_lww_is_independent_of_packet_order(self):
        s=self.l._get_sync_engine();t=self.r._get_sync_engine()
        self.l.update_account('acc_core_1010',name='Old')
        old=s.export_changes()['changes'][-1]
        self.l.update_account('acc_core_1010',name='New')
        new=s.export_changes()['changes'][-1]
        t.apply_remote_changes(self.batch([new]));t.apply_remote_changes(self.batch([old]))
        self.assertEqual(self.r.get_account_by_id('acc_core_1010').name,'New')

    def test_void_tombstone_before_insert(self):
        ident=self.tx(10000,'2026-11-11','INCOME');s=self.l._get_sync_engine();t=self.r._get_sync_engine()
        ins=[c for c in s.export_changes()['changes'] if c['entity_id']==ident and c['change_type']=='INSERT'][0]
        self.l.void_transaction(ident)
        void=[c for c in s.export_changes()['changes'] if c['entity_id']==ident and c['change_type']=='VOID'][0]
        t.apply_remote_changes(self.batch([void]));t.apply_remote_changes(self.batch([ins]))
        self.assertEqual(self.r.get_account_balance_cents('acc_core_1010'),0)

    def test_invalid_sync_rejects_entire_batch(self):
        ident=self.tx(10000,'2026-11-11','INCOME');s=self.l._get_sync_engine()
        original=[c for c in s.export_changes()['changes'] if c['entity_id']==ident][0]
        bad=copy.deepcopy(original);bad['entity_id']=generate_uuid();bad['payload']['id']=bad['entity_id']
        for p in bad['payload']['postings']:p['id']=generate_uuid();p['transaction_id']=bad['entity_id']
        bad['payload']['postings'][0]['amount_cents']+=1
        with self.assertRaises(ValueError):self.r._get_sync_engine().apply_remote_changes(self.batch([original,bad]))
        self.assertEqual(self.r.get_account_balance_cents('acc_core_1010'),0)

    def test_pagination_delivers_1005_events_once(self):
        s=self.l._get_sync_engine()
        for i in range(1005):s.record_change_event('ACCOUNT','acc_core_1010','UPDATE',{'name':str(i)})
        first=s.export_changes(limit=1000)
        self.assertTrue(first['has_more'])
        second=s.export_changes(since_hlc=first['next_cursor'])
        self.assertEqual(first['changes_count']+second['changes_count'],1005)
        self.assertFalse(second['has_more'])

    def test_sparse_goal_before_parent_is_durably_resolved(self):
        goal=self.l.create_goal('Savings',10000)
        s=self.l._get_sync_engine();full=[c for c in s.export_changes()['changes'] if c['entity_id']==goal.id][-1]
        patch=copy.deepcopy(full);patch['payload']={'id':goal.id,'name':'Renamed'};patch['change_type']='UPDATE';patch['hlc_timestamp']=s.hlc.now()
        t=self.r._get_sync_engine();result=t.apply_remote_changes(self.batch([patch]))
        self.assertEqual(result['deferred_count'],1)
        t.apply_remote_changes(self.batch([full]))
        self.assertEqual(self.r.get_goals()[0]['name'],'Renamed')
        self.assertEqual(self.r.get_goals()[0]['current_amount_cents'],0)
