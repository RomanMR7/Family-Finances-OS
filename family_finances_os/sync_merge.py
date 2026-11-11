"""Validated, replay-safe merge of offline accounting events.

Master rows are updated in place: replacing a parent would cascade-delete its
financial history. Clock values and delivered cursors are separate contracts.
"""
import hashlib
import json
from datetime import date

from .models import Posting, Transaction
from .models import require_cents

TABLES = {
    'ACCOUNT': 'accounts', 'CATEGORY': 'categories', 'OBLIGATION': 'obligations',
    'OBLIGATION_PAYMENT': 'obligation_payments', 'GOAL': 'goals',
    'GOAL_CONTRIBUTION': 'goal_contributions', 'ENVELOPE': 'envelopes',
    'ENVELOPE_OPERATION': 'envelope_operations',
}


def _meta(cursor, key, value=None):
    if value is None:
        row = cursor.execute('SELECT value FROM system_meta WHERE key=?', (key,)).fetchone()
        return json.loads(row['value']) if row else None
    cursor.execute('INSERT INTO system_meta(key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',
                   (key, json.dumps(value, ensure_ascii=False)))


def _cents(value, zero=False):
    return require_cents(value,allow_zero=zero)


def _record(cursor, item):
    cursor.execute('''INSERT INTO change_log(entity_name,entity_id,change_type,payload_json,device_id,hlc_timestamp)
                      VALUES (?,?,?,?,?,?)''',
                   (item['entity_name'], item['entity_id'], item['change_type'],
                    json.dumps(item['payload'], ensure_ascii=False), item['device_id'], item['hlc_timestamp']))


def _resolve(cursor, table, ident, code=None):
    row = cursor.execute(f'SELECT id FROM {table} WHERE id=?', (ident,)).fetchone() if ident else None
    if row:
        return row['id']
    if table == 'accounts' and code:
        row = cursor.execute('SELECT id FROM accounts WHERE code=?', (code,)).fetchone()
        if row:
            return row['id']
    return None


def _transaction(cursor, item):
    from .ledger import compute_tx_payload_hash
    payload = dict(item['payload'])
    ident = item['entity_id']
    existing = cursor.execute('SELECT * FROM transactions WHERE id=?', (ident,)).fetchone()
    if item['change_type'] == 'VOID':
        cursor.execute('UPDATE transactions SET is_voided=1,voided_reason=? WHERE id=?',
                       (payload.get('voided_reason', 'Аннулировано на другом устройстве'), ident))
        return True
    if item['change_type'] not in ('INSERT', 'UPDATE'):
        raise ValueError('Недопустимое изменение денежной операции')
    if existing:
        current = dict(existing)
        current.update(payload)
        payload = current
    if 'postings' not in payload:
        if not existing:
            return False
        payload['postings'] = [dict(p) for p in cursor.execute('SELECT * FROM postings WHERE transaction_id=?', (ident,))]
        # Compatibility with legacy two-line UPDATE events. Ambiguous splits fail closed.
        if item['payload'].get('amount_cents') is not None:
            if len(payload['postings']) != 2:
                raise ValueError('Старое событие изменения составной операции требует полной версии проводок')
            for p in payload['postings']:
                p['amount_cents'] = item['payload']['amount_cents']
        for p in payload['postings']:
            if item['payload'].get('category_id') and p['category_id']:
                p['category_id'] = item['payload']['category_id']
            if item['payload'].get('account_id'):
                acc = cursor.execute('SELECT account_type FROM accounts WHERE id=?', (p['account_id'],)).fetchone()
                if acc and acc['account_type'] in ('ASSET', 'LIABILITY'):
                    p['account_id'] = item['payload']['account_id']
        payload['payload_hash'] = None  # Old UPDATE did not recompute its header hash.
    date.fromisoformat(payload['tx_date'])
    postings = payload['postings']
    if len(postings) < 2:
        raise ValueError('Денежная операция должна содержать минимум две проводки')
    debits = credits = 0
    currencies = set()
    ids = set()
    normalized = []
    for raw in postings:
        p = dict(raw)
        _cents(p['amount_cents'])
        if p['posting_type'] not in ('DEBIT', 'CREDIT') or p['id'] in ids:
            raise ValueError('Неверные или повторные проводки')
        ids.add(p['id'])
        account_id = _resolve(cursor, 'accounts', p['account_id'], p.get('account_code'))
        if not account_id:
            return False  # Account may arrive in a later page; retained durably.
        account = cursor.execute('SELECT currency,account_type FROM accounts WHERE id=?', (account_id,)).fetchone()
        if account['account_type'] in ('ASSET', 'LIABILITY'):
            currencies.add(account['currency'])
        p['account_id'] = account_id
        if p['posting_type'] == 'DEBIT':
            debits += p['amount_cents']
        else:
            credits += p['amount_cents']
        normalized.append(p)
        if p.get('category_id') and not _resolve(cursor,'categories',p['category_id']):
            return False
    if debits != credits or debits <= 0 or len(currencies) > 1:
        raise ValueError('Нарушена двойная запись или смешаны валюты без обменной операции')
    # Verify sender identifiers before resolving seeded account aliases.
    original = Transaction(id=ident, tx_date=payload['tx_date'], tx_type=payload['tx_type'],
                           description=payload.get('description', ''), created_by_member_id=payload.get('created_by_member_id'),
                           postings=[Posting(id=p['id'], transaction_id=ident, account_id=p['account_id'],
                                             amount_cents=p['amount_cents'], posting_type=p['posting_type'],
                                             ownership_scope=p.get('ownership_scope', 'COMMON'),
                                             category_id=p.get('category_id'), purpose_allocation=p.get('purpose_allocation', 'SAFE_TO_SPEND'),
                                             note=p.get('note')) for p in postings])
    legacy = hashlib.sha256(f"{original.tx_type}:{original.description}:{sorted((p.account_id,p.amount_cents,p.posting_type,p.ownership_scope) for p in original.postings)}".encode()).hexdigest()
    claimed = payload.get('payload_hash')
    if claimed and claimed not in (compute_tx_payload_hash(original), legacy):
        raise ValueError('Не совпадает контрольная сумма денежной операции')
    if existing and item['change_type'] == 'INSERT' and existing['payload_hash'] != claimed:
        raise ValueError('Повторная денежная операция с тем же ID имеет другие параметры')
    idem = payload.get('idempotency_key')
    if idem:
        conflict = cursor.execute('SELECT id,payload_hash FROM transactions WHERE idempotency_key=? AND id<>?', (idem, ident)).fetchone()
        if conflict:
            if claimed and conflict['payload_hash'] == claimed:
                return True
            raise ValueError('Конфликт ключа повторной денежной операции')
    payload['id'] = ident
    payload['created_by_member_id'] = _resolve(cursor, 'members', payload.get('created_by_member_id'))
    payload['payload_hash'] = compute_tx_payload_hash(original)
    _upsert(cursor, 'transactions', payload, ident)
    cursor.execute('DELETE FROM postings WHERE transaction_id=?', (ident,))
    for p in normalized:
        category = _resolve(cursor, 'categories', p.get('category_id'))
        cursor.execute('''INSERT INTO postings(id,transaction_id,account_id,amount_cents,posting_type,ownership_scope,purpose_allocation,note,category_id)
                          VALUES(?,?,?,?,?,?,?,?,?)''', (p['id'],ident,p['account_id'],p['amount_cents'],p['posting_type'],
                          p.get('ownership_scope','COMMON'),p.get('purpose_allocation','SAFE_TO_SPEND'),p.get('note'),category))
    return True


def _upsert(cursor, table, values, ident):
    info = list(cursor.execute(f'PRAGMA table_info({table})'))
    allowed = {r['name'] for r in info}
    values = {k:v for k,v in values.items() if k in allowed}
    values['id'] = ident
    exists = cursor.execute(f'SELECT id FROM {table} WHERE id=?', (ident,)).fetchone()
    if exists:
        updates = [k for k in values if k != 'id']
        if updates:
            cursor.execute(f"UPDATE {table} SET {','.join(k+'=?' for k in updates)} WHERE id=?", [values[k] for k in updates]+[ident])
        return True
    required = [r['name'] for r in info if r['notnull'] and r['dflt_value'] is None and not r['pk']]
    if any(values.get(k) is None for k in required):
        return False
    columns = list(values)
    cursor.execute(f"INSERT INTO {table}({','.join(columns)}) VALUES({','.join('?' for _ in columns)})", [values[k] for k in columns])
    return True


def _entity(cursor, item):
    name, ident, kind = item['entity_name'], item['entity_id'], item['change_type']
    if name == 'TRANSACTION':
        return _transaction(cursor,item)
    if name not in TABLES:
        raise ValueError(f'Неизвестная финансовая сущность {name}')
    table = TABLES[name]
    p = dict(item['payload'])
    if name == 'OBLIGATION_PAYMENT':
        from .obligation_merge import merge_components
        date.fromisoformat(str(p['month_year'])+'-01')
        if not _resolve(cursor, 'obligations', p['obligation_id']):
            return False
        key = f"obligation_payment_components:{p['obligation_id']}:{p['month_year']}"
        incoming = p.get('components')
        if incoming is None:
            incoming = {'manual_cents': p.get('paid_amount_cents', 0), 'transactions': {}}
            if p.get('transaction_id'):
                incoming = {'manual_cents': 0, 'transactions': {p['transaction_id']: p['paid_amount_cents']}}
        components = merge_components(_meta(cursor, key), incoming, item['hlc_timestamp'],
                                      reset=kind == 'DELETE' or ('components' not in p and not p.get('transaction_id')))
        _meta(cursor, key, components)
        total = components['manual_cents'] + sum(components['transactions'].values())
        if total == 0:
            cursor.execute('DELETE FROM obligation_payments WHERE obligation_id=? AND month_year=?', (p['obligation_id'],p['month_year']))
            return True
        p['paid_amount_cents'] = _cents(total,zero=True)
        p['transaction_id'] = None  # Components retain all linked transaction identities.
        p.setdefault('paid_at', item['hlc_timestamp'])
        # Monthly payment identity is its natural key, not a fresh UUID per mark.
        row = cursor.execute('SELECT id FROM obligation_payments WHERE obligation_id=? AND month_year=?', (p['obligation_id'],p['month_year'])).fetchone()
        if row:
            ident = row['id']
        kind = 'UPDATE' if row else 'INSERT'
    for key,value in p.items():
        if key.endswith('_cents') and value is not None:
            _cents(value,zero=key not in ('amount_cents',) and key!='target_amount_cents' or name=='ENVELOPE' and key=='target_amount_cents')
    if name == 'OBLIGATION' and 'due_day' in p and (type(p['due_day']) is not int or not 1 <= p['due_day'] <= 31):
        raise ValueError('Некорректный день обязательства')
    for fk in cursor.execute(f'PRAGMA foreign_key_list({table})').fetchall():
        field, parent = fk['from'], fk['table']
        if p.get(field) and not _resolve(cursor,parent,p[field]):
            if field in ('owner_member_id','created_by_member_id','member_id'):
                p[field] = None
            else:
                return False
    if kind == 'DELETE':
        if name in ('ACCOUNT','CATEGORY','OBLIGATION','GOAL','ENVELOPE'):
            p = {'is_active':0}
        else:
            cursor.execute(f'DELETE FROM {table} WHERE id=?', (ident,))
            return True
    if name in ('GOAL', 'ENVELOPE', 'ENVELOPE_OPERATION'):
        from .reservation_events import accept_payload
        if name in ('GOAL', 'ENVELOPE') and 'current_amount_cents' in p and '_tracking_v2' not in p:
            if _meta(cursor, f'reservation-events-v2:{name}:{ident}'):
                raise ValueError('Старый клиент передаёт сумму накоплений без истории. Обновите оба устройства перед синхронизацией.')
        if not accept_payload(cursor, name, ident, p):
            return False
    return _upsert(cursor,table,p,ident)


def apply_batch(engine, sync_data):
    changes = sync_data.get('changes',[])
    if not isinstance(changes,list) or len(changes)>10000:
        raise ValueError('Некорректный размер пакета синхронизации')
    conn = engine._get_conn()
    from .db import GLOBAL_STORAGE
    shared = GLOBAL_STORAGE.is_unlocked() and conn is GLOBAL_STORAGE.get_connection()
    lock = GLOBAL_STORAGE._lock if shared else None
    if lock:lock.acquire()
    had_transaction = conn.in_transaction
    cursor = conn.cursor()
    applied = skipped = 0
    savepoint = 'sync_batch'
    cursor.execute(f'SAVEPOINT {savepoint}')
    try:
        # Sort both newly delivered events and durably deferred dependencies.
        pending = _meta(cursor,'sync_pending_events') or []
        events = pending + changes
        events.sort(key=lambda x:(str(x.get('hlc_timestamp','')),str(x.get('device_id',''))))
        deferred=[]
        for item in events:
            for field in ('entity_name','entity_id','change_type','payload','device_id','hlc_timestamp'):
                if field not in item:
                    raise ValueError('Неполное событие синхронизации')
            name,ident,hlc = item['entity_name'],item['entity_id'],item['hlc_timestamp']
            if not isinstance(item['payload'],dict) or not isinstance(hlc,str):
                raise ValueError('Неверный формат события')
            duplicate = cursor.execute('''SELECT 1 FROM change_log WHERE entity_name=? AND entity_id=?
                AND device_id=? AND hlc_timestamp=? AND change_type=? LIMIT 1''',
                (name,ident,item['device_id'],hlc,item['change_type'])).fetchone()
            if duplicate:
                skipped+=1
                continue
            # Payment DELETE events use a fresh id: share a natural-key clock.
            natural = ident
            if name=='OBLIGATION_PAYMENT':
                natural=f"{item['payload'].get('obligation_id')}:{item['payload'].get('month_year')}"
            latest_key=f'sync_version:{name}:{natural}'
            latest=_meta(cursor,latest_key)
            local = cursor.execute('SELECT MAX(hlc_timestamp) AS h FROM change_log WHERE entity_name=? AND entity_id=?', (name,ident)).fetchone()['h']
            latest=max(latest or '',local or '')
            is_void = name=='TRANSACTION' and item['change_type']=='VOID'
            if hlc<=latest and not is_void and name != 'OBLIGATION_PAYMENT':
                if name in ('GOAL', 'ENVELOPE') and '_tracking_v2' in item['payload']:
                    from .reservation_events import accept_payload
                    accept_payload(cursor, name, ident, item['payload'])
                skipped+=1
                continue
            if name=='TRANSACTION' and item['change_type']!='VOID':
                tombstone=_meta(cursor,f'sync_void:{ident}')
                voided=cursor.execute('SELECT is_voided FROM transactions WHERE id=?',(ident,)).fetchone()
                if tombstone or voided and voided['is_voided']:
                    skipped+=1
                    continue
            if not _entity(cursor,item):
                deferred.append(item)
                continue
            if name=='TRANSACTION' and item['change_type']=='VOID':
                _meta(cursor,f'sync_void:{ident}',hlc)
            _meta(cursor,latest_key,max(latest,hlc))
            _record(cursor,item)
            applied+=1
        # A parent from the same page may follow a child; resolve until stable.
        for _ in range(len(deferred)+1):
            next_round=[]
            for item in deferred:
                natural=item['entity_id']
                if item['entity_name']=='OBLIGATION_PAYMENT':
                    natural=f"{item['payload'].get('obligation_id')}:{item['payload'].get('month_year')}"
                newest=_meta(cursor,f"sync_version:{item['entity_name']}:{natural}") or ''
                if item['hlc_timestamp']<=newest and item['entity_name'] != 'OBLIGATION_PAYMENT':
                    skipped+=1
                    continue
                if _entity(cursor,item):
                    _record(cursor,item)
                    key=f"sync_version:{item['entity_name']}:{natural}"
                    _meta(cursor,key,item['hlc_timestamp'])
                    applied+=1
                else:
                    next_round.append(item)
            if len(next_round)==len(deferred):
                deferred=next_round
                break
            deferred=next_round
        from .reservation_events import recompute
        recompute(cursor)
        _meta(cursor,'sync_pending_events',deferred)
        remote_device=sync_data.get('sender_device_id')
        delivered=sync_data.get('next_cursor') or (max((x['hlc_timestamp'] for x in changes),default=None))
        if remote_device and delivered:
            cursor.execute('INSERT INTO system_meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',
                           (f'sync_last_hlc_{remote_device}',delivered))
        if shared and not had_transaction:
            GLOBAL_STORAGE.save()
        cursor.execute(f'RELEASE SAVEPOINT {savepoint}')
        remote_hlc=sync_data.get('current_hlc')
        if remote_hlc:
            engine.hlc.update(remote_hlc)
        return {'status':'success','applied_count':applied,'skipped_count':skipped,'deferred_count':len(deferred),'current_hlc':engine.hlc.now()}
    except Exception:
        cursor.execute(f'ROLLBACK TO SAVEPOINT {savepoint}')
        cursor.execute(f'RELEASE SAVEPOINT {savepoint}')
        raise
    finally:
        engine._close_if_local(conn)
        if lock:lock.release()
