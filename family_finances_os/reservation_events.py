"""Convergent informational savings tracking over immutable, unique history.

Master snapshots describe names/settings. Amounts use a stable offset plus the
set of contribution/operation IDs, so concurrent offline events are not lost by
last-writer-wins snapshots. Existing tracking is upgraded without guessing its
historical correctness: the offset preserves its exact current amount.
"""
import json
from .models import require_cents

KINDS={"GOAL":"goals","ENVELOPE":"envelopes"}


def _key(kind,ident):
    return "reservation-events-v2:"+kind+":"+ident


def _get(cursor,key):
    row=cursor.execute("SELECT value FROM system_meta WHERE key=?",(key,)).fetchone()
    return json.loads(row["value"]) if row else None


def _put(cursor,key,value):
    cursor.execute("INSERT INTO system_meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                   (key,json.dumps(value,ensure_ascii=False,sort_keys=True)))


def signed_cents(value):
    if type(value) is not int:
        raise ValueError("Расчёт накоплений должен содержать целые копейки.")
    require_cents(abs(value),allow_zero=True)
    return value


def _effective_amount(cursor,amount,transaction_id):
    if not transaction_id:
        return amount
    tx=cursor.execute("SELECT is_voided,tx_type FROM transactions WHERE id=?",(transaction_id,)).fetchone()
    if tx is None:
        # Legacy packets can arrive without their dependencies. The history is
        # retained and the final recomputation occurs when its transaction lands.
        return amount
    if tx["is_voided"]:
        return 0
    sums=cursor.execute("SELECT posting_type,SUM(amount_cents) AS cents FROM postings WHERE transaction_id=? GROUP BY posting_type",
                        (transaction_id,)).fetchall()
    totals={row["posting_type"]:row["cents"] for row in sums}
    if totals.get("DEBIT") != totals.get("CREDIT") or not totals.get("DEBIT"):
        raise ValueError("Связанный перевод накоплений нарушает двойную запись.")
    return totals["DEBIT"]


def history_total(cursor,kind,ident):
    if kind=="GOAL":
        return sum(_effective_amount(cursor,row["amount_cents"],row["transaction_id"])
                   for row in cursor.execute("SELECT * FROM goal_contributions WHERE goal_id=?",(ident,)).fetchall())
    rows=cursor.execute("SELECT * FROM envelope_operations WHERE envelope_id=? OR target_envelope_id=?",
                         (ident,ident)).fetchall()
    total=0
    for row in rows:
        metadata=_get(cursor,_key("OP",row["id"])) or {}
        amount=_effective_amount(cursor,row["amount_cents"],metadata.get("transaction_id"))
        if row["operation_type"]=="TRANSFER":
            total+=amount if row["target_envelope_id"]==ident else -amount
        else:
            total+=amount if row["operation_type"]=="DEPOSIT" else -amount
    return total


def ensure_baseline(cursor,kind,ident,base_cents=None):
    if kind not in KINDS:
        raise ValueError("Неизвестный тип накоплений.")
    existing=_get(cursor,_key(kind,ident))
    if existing:
        return existing
    row=cursor.execute(f"SELECT current_amount_cents FROM {KINDS[kind]} WHERE id=?",(ident,)).fetchone()
    if row is None:
        raise ValueError("Объект накоплений не найден.")
    if base_cents is None:
        base_cents=row["current_amount_cents"]-history_total(cursor,kind,ident)
    baseline={"version":2,"role":"baseline","base_cents":signed_cents(base_cents)}
    _put(cursor,_key(kind,ident),baseline)
    return baseline


def annotate_snapshot(cursor,kind,ident,payload):
    result=dict(payload)
    if kind in KINDS:
        result["_tracking_v2"]=ensure_baseline(cursor,kind,ident)
    elif kind=="ENVELOPE_OPERATION":
        metadata=_get(cursor,_key("OP",ident))
        if metadata:
            result["_tracking_v2"]=metadata
    return result


def register_operation(cursor,operation_id,transaction_id=None):
    metadata={"version":2,"role":"operation","transaction_id":transaction_id}
    _put(cursor,_key("OP",operation_id),metadata)


def accept_payload(cursor,kind,ident,payload):
    """Receive metadata after dependencies validate and before generic upsert.

    Returns False only when a bank transaction dependency has not arrived yet.
    A divergent legacy baseline fails closed instead of silently picking money.
    """
    metadata=payload.get("_tracking_v2")
    if metadata is None:
        return True
    if not isinstance(metadata,dict) or metadata.get("version")!=2:
        raise ValueError("Неизвестная версия событий накоплений.")
    if kind in KINDS:
        if metadata.get("role")!="baseline":
            raise ValueError("Некорректная база накоплений.")
        base=signed_cents(metadata.get("base_cents"))
        prior=_get(cursor,_key(kind,ident))
        if prior and prior["base_cents"]!=base:
            raise ValueError("Базы истории накоплений на устройствах различаются; нужна сверка прежних данных.")
        _put(cursor,_key(kind,ident),{"version":2,"role":"baseline","base_cents":base})
    elif kind=="ENVELOPE_OPERATION":
        if metadata.get("role")!="operation":
            raise ValueError("Некорректное событие конверта.")
        tx_id=metadata.get("transaction_id")
        if tx_id and not cursor.execute("SELECT id FROM transactions WHERE id=?",(tx_id,)).fetchone():
            return False
        prior=_get(cursor,_key("OP",ident))
        if prior and prior.get("transaction_id")!=tx_id:
            raise ValueError("Операция конверта связана с другим денежным переводом.")
        register_operation(cursor,ident,tx_id)
    return True


def value(cursor,kind,ident,stored=None):
    baseline=_get(cursor,_key(kind,ident))
    if baseline is None:
        if stored is not None:
            return stored
        row=cursor.execute(f"SELECT current_amount_cents FROM {KINDS[kind]} WHERE id=?",(ident,)).fetchone()
        return row["current_amount_cents"]
    return signed_cents(baseline["base_cents"]+history_total(cursor,kind,ident))


def recompute(cursor):
    """Rebuild upgraded snapshots only; legacy history is never inferred here."""
    for kind,table in KINDS.items():
        for row in cursor.execute(f"SELECT id,current_amount_cents"+(",target_amount_cents" if kind=="GOAL" else "")+f" FROM {table}").fetchall():
            baseline=_get(cursor,_key(kind,row["id"]))
            if not baseline:
                continue
            current=value(cursor,kind,row["id"],row["current_amount_cents"])
            if kind=="GOAL":
                if current<0:
                    raise ValueError("История цели даёт отрицательное накопление; требуется сверка базы.")
                cursor.execute("UPDATE goals SET current_amount_cents=?,is_completed=? WHERE id=?",
                               (current,int(current>=row["target_amount_cents"]),row["id"]))
            else:
                # Concurrent offline withdrawals can exceed a shared allocation.
                # Preserve the deficit visibly instead of clamping away money.
                cursor.execute("UPDATE envelopes SET current_amount_cents=? WHERE id=?",(current,row["id"]))
