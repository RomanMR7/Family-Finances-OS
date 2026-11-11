"""Merge paid allocations by transaction identity, with explicit manual/reset clocks.

Financial transfers remain immutable ledger facts.  This state only allocates a
part of a transaction to a recurring obligation; it never creates a money entry.
"""
from copy import deepcopy
from .models import require_cents


def merge_components(local, incoming, event_hlc, *, reset=False):
    """Union independent allocations; manual mark/unmark replaces the older baseline.

    `reset=True` means that this event itself is a manual snapshot or an unmark.
    The caller must persist even an empty reset state and must not discard older
    allocation events using a whole-payment Last-Write-Wins check.
    """
    if not isinstance(event_hlc, str) or not event_hlc:
        raise ValueError("У компонента оплаты нет версии события.")
    left = deepcopy(local or {})
    right = deepcopy(incoming or {})
    if not isinstance(left, dict) or not isinstance(right, dict):
        raise ValueError("Некорректные компоненты оплаты.")
    if reset:
        right["reset_hlc"] = event_hlc
        right["transactions"] = {}
        right["transaction_hlcs"] = {}
    left_reset = left.get("reset_hlc") or ""
    right_reset = right.get("reset_hlc") or ""
    if not isinstance(left_reset, str) or not isinstance(right_reset, str):
        raise ValueError("Некорректная версия сброса оплаты.")
    reset_hlc = max(left_reset, right_reset)
    baseline = right if right_reset > left_reset else left
    if right_reset == left_reset:
        # Equal reset versions must represent the same manual snapshot.
        left_manual = require_cents(left.get("manual_cents", 0), allow_zero=True)
        right_manual = require_cents(right.get("manual_cents", 0), allow_zero=True)
        if left_reset and left_manual != right_manual:
            raise ValueError("Конфликт одинаковой версии ручной оплаты.")
        # Legacy snapshots have no reset marker. Preserve their explicit manual base.
        manual = max(left_manual, right_manual)
    else:
        manual = require_cents(baseline.get("manual_cents", 0), allow_zero=True)
    transactions = {}
    clocks = {}
    for state, fallback in ((left, ""), (right, event_hlc)):
        entries = state.get("transactions", {})
        versions = state.get("transaction_hlcs", {})
        if not isinstance(entries, dict) or not isinstance(versions, dict):
            raise ValueError("Некорректный набор связанных платежей.")
        for ident, amount in entries.items():
            require_cents(amount)
            if not isinstance(ident, str) or not ident:
                raise ValueError("У связанного платежа нет идентификатора.")
            clock = versions.get(ident, fallback)
            if not isinstance(clock, str):
                raise ValueError("Некорректная версия связанного платежа.")
            if reset_hlc and clock <= reset_hlc:
                continue
            if ident in transactions and transactions[ident] != amount:
                raise ValueError("Одна операция распределена с разными суммами.")
            transactions[ident] = amount
            clocks[ident] = max(clock, clocks.get(ident, ""))
    return {"manual_cents": manual, "transactions": transactions,
            "transaction_hlcs": clocks, "reset_hlc": reset_hlc, "version": 2}
