"""Read-only RUB reporting with explicit calendar and signed-flow contracts."""
import calendar
import re
from datetime import datetime, date, timedelta
from decimal import Decimal, ROUND_HALF_UP

from .models import cents_to_rubles, require_cents


def rounded_ratio(numerator, denominator):
    return int((Decimal(numerator)/Decimal(denominator)).quantize(Decimal(1),rounding=ROUND_HALF_UP))


def reporting_period(period, start_date, end_date, today, first_date=None):
    if bool(start_date) != bool(end_date):
        raise ValueError('Для произвольного периода нужны обе даты')
    if start_date:
        start,end=date.fromisoformat(start_date),date.fromisoformat(end_date)
        label=f'{start.isoformat()} — {end.isoformat()}'
    elif re.fullmatch(r'\d{4}-\d{2}',period):
        start=date.fromisoformat(period+'-01')
        end=start.replace(day=calendar.monthrange(start.year,start.month)[1])
        label=period
    elif period=='prev_month':
        end=today.replace(day=1)-timedelta(days=1)
        start=end.replace(day=1)
        label=f'Предыдущий месяц ({start:%m.%Y})'
    elif period in ('30d','90d'):
        count=int(period[:-1]);start=today-timedelta(days=count-1);end=today
        label=f'Последние {count} дней'
    elif period=='all':
        start=date.fromisoformat(first_date) if first_date else today
        end=today;label='За всё время'
    elif period=='current_month':
        start=today.replace(day=1);end=start.replace(day=calendar.monthrange(today.year,today.month)[1])
        label=f'Текущий месяц ({start:%m.%Y})'
    else:
        raise ValueError('Неизвестный период аналитики')
    if start>end:
        raise ValueError('Начало периода должно быть не позже конца')
    return start,end,label,max(1,(min(today,end)-start).days+1)


def analytics(ledger,period='current_month',start_date=None,end_date=None,today=None):
    today=today or datetime.now().date()
    conn=ledger._get_conn()
    try:
        first=conn.execute('SELECT MIN(tx_date) AS d FROM transactions WHERE is_voided=0 AND tx_date<=?',(today.isoformat(),)).fetchone()['d']
        start,end,label,days=reporting_period(period,start_date,end_date,today,first)
        # A neutral P&L account has no monetary currency of its own. Use the
        # financial counterparty of the transaction to select RUB reporting.
        rows=list(conn.execute('''SELECT p.*,t.tx_date,t.description,t.created_by_member_id,
                    a.account_type,c.name AS category_name,c.icon AS category_icon
                FROM postings p JOIN transactions t ON t.id=p.transaction_id
                JOIN accounts a ON a.id=p.account_id LEFT JOIN categories c ON c.id=p.category_id
                WHERE t.is_voided=0 AND a.account_type IN ('INCOME','EXPENSE')
                AND t.tx_date BETWEEN ? AND ?
                AND NOT EXISTS(SELECT 1 FROM postings fx JOIN accounts fa ON fa.id=fx.account_id
                               WHERE fx.transaction_id=t.id AND fa.account_type IN ('ASSET','LIABILITY') AND fa.currency<>'RUB')''',
                (start.isoformat(),min(end,today).isoformat())))
    finally:
        ledger._close_if_local(conn)
    expenses=[];incomes=[]
    for row in rows:
        item=dict(row)
        positive = row['posting_type']==('DEBIT' if row['account_type']=='EXPENSE' else 'CREDIT')
        item['signed_cents']=row['amount_cents']*(1 if positive else -1)
        (expenses if row['account_type']=='EXPENSE' else incomes).append(item)
    expense=sum(x['signed_cents'] for x in expenses);income=sum(x['signed_cents'] for x in incomes)
    categories={};members={}
    labels={'COMMON':('Общие семейные','👨‍👩‍👧‍👦'),'PERSONAL_HUSBAND':('Муж','👨'),'PERSONAL_WIFE':('Жена','👩'),'OTHER':('Прочие','👤')}
    for scope,(text,icon) in labels.items():
        members[scope]={'scope':scope,'label':text,'icon':icon,'amount_cents':0,'_tx':set()}
    for r in expenses:
        cid=r['category_id'] or 'uncategorized'
        cat=categories.setdefault(cid,{'id':cid,'name':r['category_name'] or 'Без категории','icon':r['category_icon'] or 'tag','amount_cents':0,'_tx':set()})
        cat['amount_cents']+=r['signed_cents'];cat['_tx'].add(r['transaction_id'])
        scope=r['ownership_scope'] if r['ownership_scope'] in members else 'OTHER'
        members[scope]['amount_cents']+=r['signed_cents'];members[scope]['_tx'].add(r['transaction_id'])
    def decorate(items):
        for item in items:
            item['amount_rub']=cents_to_rubles(item['amount_cents'])
            item['tx_count']=len(item.pop('_tx'))
            item['percent']=round(item['amount_cents']/expense*100,1) if expense>0 else 0.0
        return items
    categories=decorate(sorted(categories.values(),key=lambda x:x['amount_cents'],reverse=True))
    members=decorate([m for m in members.values() if m['_tx'] or m['scope']!='OTHER'])
    # Rank whole expense transactions, not individual split posting lines.
    txs={}
    for r in expenses:
        item=txs.setdefault(r['transaction_id'],{'transaction_id':r['transaction_id'],'date':r['tx_date'],'description':r['description'],
                         'amount_cents':0,'category_name':r['category_name'] or 'Без категории','category_icon':r['category_icon'] or 'tag'})
        item['amount_cents']+=r['signed_cents']
    top=sorted((x for x in txs.values() if x['amount_cents']>0),key=lambda x:x['amount_cents'],reverse=True)[:5]
    for x in top:x['amount_rub']=cents_to_rubles(x['amount_cents'])
    avg=rounded_ratio(expense,days)
    overview=ledger.get_financial_overview()
    liquid=overview['common_liquid_assets_cents']
    return {'period':period,'period_label':label,'start_date':start.isoformat(),'end_date':end.isoformat(),'days_count':days,
            'total_income_cents':income,'total_income_rub':cents_to_rubles(income),'total_expense_cents':expense,'total_expense_rub':cents_to_rubles(expense),
            'net_savings_cents':income-expense,'net_savings_rub':cents_to_rubles(income-expense),
            'savings_rate_percent':round((income-expense)/income*100,1) if income>0 else 0.0,
            'daily_avg_expense_cents':avg,'daily_avg_expense_rub':cents_to_rubles(avg),'cash_runway_days':max(0,liquid//avg) if avg>0 else None,
            'categories':categories,'members':members,'top_expenses':top,'reporting_currency':'RUB',
            'currency_note':'Сводные показатели рассчитаны только по рублёвым операциям; валютные счета показаны отдельно.'}


def forecast(ledger,days=30,include_burn_rate=True,custom_daily_burn_cents=None,safety_buffer_cents=0,today=None):
    today=today or datetime.now().date()
    if type(days) is not int:raise ValueError('Горизонт должен быть целым числом дней')
    days=min(max(days,7),90)
    require_cents(safety_buffer_cents,allow_zero=True)
    if custom_daily_burn_cents is not None:require_cents(custom_daily_burn_cents,allow_zero=True)
    overview=ledger.get_financial_overview();liquid=overview['common_liquid_assets_cents'];debt=overview['credit_cards']['total_debt_cents']
    start=liquid-debt;balance=start;minimum=start
    conn=ledger._get_conn()
    try:
        # Exclude actual linked fixed payments, not every purchase in their category.
        hist=list(conn.execute('''SELECT p.amount_cents,p.posting_type,t.tx_date,t.id
              FROM postings p JOIN transactions t ON t.id=p.transaction_id JOIN accounts a ON a.id=p.account_id
              WHERE t.is_voided=0 AND a.account_type='EXPENSE' AND t.tx_date BETWEEN ? AND ?
              AND NOT EXISTS(SELECT 1 FROM obligation_payments op WHERE op.transaction_id=t.id)
              AND NOT EXISTS(SELECT 1 FROM postings fx JOIN accounts fa ON fa.id=fx.account_id
                    WHERE fx.transaction_id=t.id AND fa.account_type IN ('ASSET','LIABILITY') AND fa.currency<>'RUB')''',
              ((today-timedelta(days=29)).isoformat(),today.isoformat())))
    finally:ledger._close_if_local(conn)
    variable=sum(x['amount_cents']*(1 if x['posting_type']=='DEBIT' else -1) for x in hist if x['amount_cents']<10000000)
    active_days=len({x['tx_date'] for x in hist if x['posting_type']=='DEBIT'})
    if not include_burn_rate:burn=0;source='disabled'
    elif custom_daily_burn_cents is not None:burn=custom_daily_burn_cents;source='custom'
    elif active_days<3:burn=0;source='cold_start_or_disabled'
    else:burn=max(0,rounded_ratio(variable,30));source='historical_30d'
    months={};milestones=[];timeline=[]
    def obligations(when):
        key=when.strftime('%Y-%m')
        if key not in months:
            months[key]=[o for o in ledger.get_obligations(key) if o.get('currency','RUB')=='RUB']
        return months[key]
    # Conservative explicit carry-forward of this month's unpaid due/overdue
    # bills. It is a day-zero event; future months retain their own paid state.
    day_zero=[]
    for o in obligations(today):
        if min(o['due_day'],calendar.monthrange(today.year,today.month)[1])<=today.day and o['remaining_cents']>0:
            amount=o['remaining_cents'];balance-=amount
            day_zero.append({'type':'OBLIGATION','name':o['name'],'amount_cents':amount,'amount_rub':cents_to_rubles(amount)})
    minimum=min(minimum,balance)
    first_date=today.isoformat() if balance<0 else None
    first_amount=abs(balance) if balance<0 else 0
    first_trigger='Начальный дефицит' if start<0 else (day_zero[0]['name'] if day_zero and balance<0 else None)
    soft_date=today.isoformat() if balance<safety_buffer_cents else None
    for step in range(1,days+1):
        when=today+timedelta(days=step);events=[];obligation_sum=0
        for o in obligations(when):
            due=min(o['due_day'],calendar.monthrange(when.year,when.month)[1])
            if when.day==due and o['remaining_cents']>0:
                amount=o['remaining_cents'];obligation_sum+=amount
                event={'type':'OBLIGATION','name':o['name'],'amount_cents':amount,'amount_rub':cents_to_rubles(amount)}
                events.append(event);milestones.append({'date':when.isoformat(),'day':step,'label':o['name'],'amount_cents':amount})
        if burn:events.append({'type':'BURN_RATE','name':'Повседневные траты','amount_cents':burn,'amount_rub':cents_to_rubles(burn)})
        delta=-(obligation_sum+burn);balance+=delta;minimum=min(minimum,balance)
        if balance<0 and first_date is None:
            first_date=when.isoformat();first_amount=abs(balance);first_trigger=events[0]['name'] if events else 'Накопленный дефицит'
        if balance<safety_buffer_cents and soft_date is None:soft_date=when.isoformat()
        timeline.append({'day_index':step,'date':when.isoformat(),'day_formatted':when.strftime('%d.%m'),'day_of_week':when.strftime('%a'),
                         'balance_cents':balance,'balance_rub':cents_to_rubles(balance),'is_deficit':balance<0,
                         'net_change_cents':delta,'net_change_rub':cents_to_rubles(delta),'events':events})
    monthly=sum(o['amount_cents'] for o in obligations(today));daily=burn+rounded_ratio(monthly,30)
    return {'forecast_days':days,'start_date':today.isoformat(),'end_date':(today+timedelta(days=days)).isoformat(),
            'starting_liquid_cents':liquid,'starting_liquid_rub':cents_to_rubles(liquid),'credit_debt_cents':debt,'credit_debt_rub':cents_to_rubles(debt),
            'effective_start_cents':start,'effective_start_rub':cents_to_rubles(start),'day_zero_balance_cents':start-sum(e['amount_cents'] for e in day_zero),
            'day_zero_events':day_zero,'emergency_reserves_cents':overview['emergency_reserves_cents'],'emergency_reserves_rub':overview['emergency_reserves_rub'],
            'daily_burn_cents':burn,'daily_burn_rub':cents_to_rubles(burn),'burn_rate_source':source,'active_expense_days':active_days,
            'has_deficit':first_date is not None,'first_deficit_date':first_date,'first_deficit_cents':first_amount,'first_deficit_rub':cents_to_rubles(first_amount),
            'first_deficit_trigger':first_trigger,'min_projected_balance_cents':minimum,'min_projected_balance_rub':cents_to_rubles(minimum),
            'cash_runway_days':max(0,start//daily) if daily>0 else None,'milestones':milestones,'timeline':timeline,
            'safety_buffer_cents':safety_buffer_cents,'has_soft_gap':soft_date is not None,'first_soft_gap_date':soft_date,
            'reporting_currency':'RUB','model_note':'Оценка без будущих доходов. Неоплаченные счета со сроком сегодня или ранее в текущем месяце учтены в день 0. Цели и конверты — информационные планы, не дополнительные вычеты.'}
