import json
"""

Family Finances OS - Comprehensive Double-Entry Ledger Engine

Implements Stage 2: Full Account Lifecycle, Internal Transfers, Credit Card Isolation,

Personal-for-Common Expense Tracking, and Multi-Balance Financial Overviews.

"""

import hashlib

import sqlite3
from contextlib import contextmanager, nullcontext
from functools import wraps
import threading
from datetime import date

from typing import Dict, List, Optional, Tuple, Any

from family_finances_os.db import get_connection

from family_finances_os.models import (

    Account,

    Posting,

    Transaction,

    Category,

    Obligation,

    ObligationPayment,

    Goal,

    GoalContribution,

    Envelope,

    EnvelopeOperation,

    generate_uuid,

    current_iso_time,

    rubles_to_cents,

    cents_to_rubles

)
from family_finances_os.models import require_cents


def atomic_operation(method):
    @wraps(method)
    def wrapped(self, *args, **kwargs):
        with self.atomic():
            return method(self, *args, **kwargs)
    return wrapped

def compute_tx_payload_hash(tx: Transaction) -> str:

    """

    Compute a deterministic canonical SHA-256 hash of the transaction payload

    to detect any tampering or parameter mismatch under the same idempotency key.

    """

    postings_repr = sorted([
        (p.account_id, p.amount_cents, p.posting_type, p.ownership_scope,
         p.purpose_allocation, p.category_id or "") for p in tx.postings
    ])
    canonical_str = json.dumps([tx.tx_date, tx.tx_type, tx.description,
        tx.created_by_member_id, postings_repr], ensure_ascii=False, separators=(",", ":"))
    return "v2:" + hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()


DEBT_CATEGORY_MAP = {
    "CREDIT_CARD": "cat_debts_credit_card",
    "CONSUMER_LOAN": "cat_debts_consumer",
    "MORTGAGE": "cat_debts_mortgage",
    "AUTO_LOAN": "cat_debts_auto",
    "INSTALLMENT_BNPL": "cat_debts_bnpl",
    "PERSONAL_DEBT": "cat_debts_personal",
    "LOAN": "cat_debts_consumer"
}

class LedgerEngine:

    def __init__(self, conn_or_path: Any = None):

        self.conn_or_path = conn_or_path

        self._sync_engine = None
        self._atomic_depth = 0
        self._atomic_conn = None
        self._command_lock = threading.RLock()

        try:

            from family_finances_os.sync import P2PSyncEngine

            self._sync_engine = P2PSyncEngine(conn_or_path=self.conn_or_path)

        except Exception:

            self._sync_engine = None

    def _get_sync_engine(self):

        if self._sync_engine is None:

            from family_finances_os.sync import P2PSyncEngine

            self._sync_engine = P2PSyncEngine(conn_or_path=self.conn_or_path)

        return self._sync_engine

    def _get_conn(self) -> sqlite3.Connection:

        if self._atomic_conn is not None:
            return self._atomic_conn

        from family_finances_os.db import get_db_connection

        return get_db_connection(self.conn_or_path)

    def _close_if_local(self, conn: sqlite3.Connection):

        if self._atomic_depth:
            return

        if isinstance(self.conn_or_path, sqlite3.Connection):

            return

        from family_finances_os.db import GLOBAL_STORAGE

        if GLOBAL_STORAGE.is_unlocked() and conn is GLOBAL_STORAGE.get_connection():

            return

        if self.conn_or_path:

            conn.close()

            return

        from family_finances_os.config import DB_PATH

        if DB_PATH.exists() and not GLOBAL_STORAGE.is_unlocked():

            conn.close()

    def _save_if_encrypted(self):

        if self._atomic_depth:
            return

        from family_finances_os.db import GLOBAL_STORAGE

        if GLOBAL_STORAGE.is_unlocked() and (self.conn_or_path is None or self.conn_or_path is GLOBAL_STORAGE._active_conn):

            GLOBAL_STORAGE.save()

    def _commit(self, conn):
        if not self._atomic_depth:
            conn.commit()

    @contextmanager
    def atomic(self):
        """Serialize commands and use one connection/rollback boundary for nested calls."""
        from family_finances_os.db import GLOBAL_STORAGE
        storage_lock = GLOBAL_STORAGE._lock if self.conn_or_path is None or self.conn_or_path is GLOBAL_STORAGE._active_conn else nullcontext()
        with self._command_lock, storage_lock:
            outer = self._atomic_depth == 0
            if outer:
                conn = self._get_conn()
                self._atomic_conn = conn
                had_transaction = conn.in_transaction
            else:
                conn = self._atomic_conn
                had_transaction = True
            savepoint = "ffos_" + generate_uuid().replace("-", "")
            conn.execute("SAVEPOINT " + savepoint)
            self._atomic_depth += 1
            try:
                if outer:
                    from .reservation_events import ensure_baseline
                    for kind, table in (("GOAL", "goals"), ("ENVELOPE", "envelopes")):
                        for row in conn.execute(f"SELECT id FROM {table}").fetchall():
                            ensure_baseline(conn.cursor(), kind, row["id"])
                yield conn
                if outer:
                    from .reservation_events import recompute
                    recompute(conn.cursor())
                if outer and not had_transaction and conn is GLOBAL_STORAGE._active_conn and GLOBAL_STORAGE.is_unlocked():
                    # Serialize the pending state before releasing its rollback boundary.
                    # A failed encrypted atomic write therefore leaves no committed mutation.
                    GLOBAL_STORAGE.save()
                conn.execute("RELEASE SAVEPOINT " + savepoint)
            except Exception:
                if conn.in_transaction:
                    try:
                        conn.execute("ROLLBACK TO SAVEPOINT " + savepoint)
                        conn.execute("RELEASE SAVEPOINT " + savepoint)
                    except sqlite3.OperationalError:
                        conn.rollback()
                raise
            finally:
                self._atomic_depth -= 1
                if outer:
                    self._atomic_conn = None
                    self._close_if_local(conn)

    def _transaction_snapshot(self, cursor, transaction_id):
        cursor.execute("SELECT * FROM transactions WHERE id = ?", (transaction_id,))
        row = cursor.fetchone()
        if row is None:
            raise ValueError("Операция не найдена.")
        payload = dict(row)
        cursor.execute("SELECT p.*,a.code AS account_code FROM postings p JOIN accounts a ON a.id=p.account_id WHERE p.transaction_id = ? ORDER BY p.id", (transaction_id,))
        payload["postings"] = [dict(p) for p in cursor.fetchall()]
        return payload

    @staticmethod
    def _obligation_month(value):
        from datetime import datetime
        value = value or datetime.now().strftime("%Y-%m")
        if not isinstance(value, str) or len(value) != 7:
            raise ValueError("Месяц должен быть в формате ГГГГ-ММ.")
        try:
            date.fromisoformat(value + "-01")
        except ValueError:
            raise ValueError("Некорректный календарный месяц.") from None
        return value

    @staticmethod
    def _obligation_components_key(obligation_id, month):
        return f"obligation_payment_components:{obligation_id}:{month}"

    def _obligation_paid_total(self, cursor, components, currency=None):
        total = require_cents(components.get("manual_cents", 0), allow_zero=True)
        for transaction_id, amount in components.get("transactions", {}).items():
            require_cents(amount)
            if currency:
                currencies = {r['currency'] for r in cursor.execute("SELECT DISTINCT a.currency FROM postings p JOIN accounts a ON a.id=p.account_id WHERE p.transaction_id=? AND a.account_type IN ('ASSET','LIABILITY')", (transaction_id,))}
                if currencies and currencies != {currency}:
                    continue
            cursor.execute("SELECT COALESCE(SUM(p.amount_cents),0) AS amount FROM postings p JOIN transactions t ON t.id=p.transaction_id JOIN accounts a ON a.id=p.account_id WHERE t.id=? AND t.is_voided=0 AND p.posting_type='DEBIT' AND a.account_type IN ('EXPENSE','LIABILITY')", (transaction_id,))
            current = cursor.fetchone()["amount"]
            total += min(amount, current)
        return total

    # ---------------------------------------------------------

    # 1. Chart of Accounts Seeding & Lifecycle

    # ---------------------------------------------------------

    def seed_default_chart_of_accounts(self) -> List[str]:

        """

        Create default core chart of accounts with predefined accounting codes and deterministic IDs.

        """

        accounts = [

            # 1000 Assets (Common & Family Member Cards)

            Account(id="acc_core_1010", code="1010", name="Основная семейная карта", account_type="ASSET", subtype="DEBIT_CARD", ownership_scope="COMMON"),

            Account(id="acc_core_1020", code="1020", name="Семейные наличные", account_type="ASSET", subtype="CASH", ownership_scope="COMMON"),

            Account(id="acc_core_1030", code="1030", name="Накопительный счет (Резерв)", account_type="ASSET", subtype="SAVINGS", ownership_scope="COMMON"),

            Account(id="acc_core_1011", code="1011", name="Карта Мужа", account_type="ASSET", subtype="DEBIT_CARD", ownership_scope="COMMON"),

            Account(id="acc_core_1012", code="1012", name="Карта Жены", account_type="ASSET", subtype="DEBIT_CARD", ownership_scope="COMMON"),

            # 2000 Liabilities

            Account(id="acc_core_2010", code="2010", name="Потребительский кредит", account_type="LIABILITY", subtype="LOAN", ownership_scope="COMMON"),

            Account(id="acc_core_2020", code="2020", name="Кредитная карта", account_type="LIABILITY", subtype="CREDIT_CARD", ownership_scope="COMMON", credit_limit_cents=10000000),

            # 3000 Equity (Unified Single Family Capital)

            Account(id="acc_core_3010", code="3010", name="Общий семейный капитал", account_type="EQUITY", subtype="COMMON_EQUITY", ownership_scope="COMMON"),

            Account(id="acc_core_3090", code="3090", name="Дефицит корзин (BUCKET_DEFICIT)", account_type="EQUITY", subtype="DEFICIT", ownership_scope="COMMON"),

            # 4000 Income

            Account(id="acc_core_4010", code="4010", name="Основная зарплата", account_type="INCOME", subtype="SALARY", ownership_scope="COMMON"),

            Account(id="acc_core_4020", code="4020", name="Пассивный доход / Проценты", account_type="INCOME", subtype="INVESTMENT", ownership_scope="COMMON"),

            # 5000 Expense

            Account(id="acc_core_5010", code="5010", name="Продукты и питание", account_type="EXPENSE", subtype="GROCERIES", ownership_scope="COMMON"),

            Account(id="acc_core_5020", code="5020", name="Жилье и коммунальные услуги", account_type="EXPENSE", subtype="HOUSING", ownership_scope="COMMON"),

            Account(id="acc_core_5030", code="5030", name="Транспорт и авто", account_type="EXPENSE", subtype="TRANSPORT", ownership_scope="COMMON"),

            Account(id="acc_core_5910", code="5910", name="Проценты по кредитам", account_type="EXPENSE", subtype="FINANCIAL_EXPENSE", ownership_scope="COMMON"),

        ]

        created_ids = []

        conn = self._get_conn()

        cursor = conn.cursor()

        for acc in accounts:

            cursor.execute("""

            INSERT OR IGNORE INTO accounts 

            (id, code, name, account_type, subtype, currency, ownership_scope, owner_member_id, description, credit_limit_cents, initial_balance_cents, is_active)

            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)

            """, (acc.id, acc.code, acc.name, acc.account_type, acc.subtype, acc.currency, acc.ownership_scope, acc.owner_member_id, acc.description, acc.credit_limit_cents, acc.initial_balance_cents))

            created_ids.append(acc.id)

        conn.commit()

        self._save_if_encrypted()

        self._close_if_local(conn)

        return created_ids

    @atomic_operation
    def create_account(

        self,

        name: str,

        account_type: str,

        subtype: str,

        ownership_scope: str,

        owner_member_id: Optional[str] = None,

        code: Optional[str] = None,

        description: Optional[str] = None,

        credit_limit_cents: int = 0,

        initial_balance_cents: int = 0,

        currency: str = "RUB"

    ) -> Account:

        """

        Create a new financial account and optionally record an opening balance transaction.

        """

        if not name.strip():

            raise ValueError("Название счета не может быть пустым.")

        if account_type not in ("ASSET", "LIABILITY", "EQUITY", "INCOME", "EXPENSE"):

            raise ValueError(f"Недопустимый тип счета: {account_type}")

        require_cents(credit_limit_cents, allow_zero=True)
        require_cents(initial_balance_cents, allow_zero=True)
        currency = str(currency).strip().upper()
        if len(currency) != 3 or not currency.isascii() or not currency.isalpha():
            raise ValueError("Валюта должна быть трёхбуквенным кодом.")
        if initial_balance_cents and account_type not in ("ASSET", "LIABILITY"):
            raise ValueError("Начальный остаток поддерживается для активов и обязательств.")
        if credit_limit_cents < 0:

            raise ValueError("Кредитный лимит не может быть отрицательным.")

        if initial_balance_cents < 0:

            raise ValueError("Начальный остаток не может быть отрицательным.")

        account_id = generate_uuid()

        if not code:

            code = f"ACC_{account_id[:8].upper()}"

        account = Account(

            id=account_id,

            code=code,

            name=name.strip(),

            account_type=account_type,

            subtype=subtype,

            currency=currency,

            ownership_scope=ownership_scope,

            owner_member_id=owner_member_id,

            description=description.strip() if description else None,

            credit_limit_cents=credit_limit_cents,

            initial_balance_cents=initial_balance_cents,

            is_active=True

        )

        conn = self._get_conn()

        cursor = conn.cursor()

        try:

            cursor.execute("""

            INSERT INTO accounts 

            (id, code, name, account_type, subtype, currency, ownership_scope, owner_member_id, description, credit_limit_cents, initial_balance_cents, is_active)

            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)

            """, (account.id, account.code, account.name, account.account_type, account.subtype, account.currency, account.ownership_scope, account.owner_member_id, account.description, account.credit_limit_cents, account.initial_balance_cents))

            # Record Opening Balance transaction if initial_balance_cents > 0

            if initial_balance_cents > 0:

                equity_code = "3010"

                cursor.execute("SELECT id FROM accounts WHERE code = ?", (equity_code,))

                equity_row = cursor.fetchone()

                equity_account_id = equity_row["id"] if equity_row else None

                if equity_account_id:

                    tx_id = generate_uuid()

                    tx_date = current_iso_time()[:10]

                    postings = []

                    if account_type == "ASSET":

                        # DEBIT: Asset Account, CREDIT: Equity

                        postings.append(Posting(id=generate_uuid(), transaction_id=tx_id, account_id=account.id, amount_cents=initial_balance_cents, posting_type="DEBIT", ownership_scope=ownership_scope))

                        postings.append(Posting(id=generate_uuid(), transaction_id=tx_id, account_id=equity_account_id, amount_cents=initial_balance_cents, posting_type="CREDIT", ownership_scope=ownership_scope))

                    elif account_type == "LIABILITY":

                        # DEBIT: Equity, CREDIT: Liability (Starting Debt)

                        postings.append(Posting(id=generate_uuid(), transaction_id=tx_id, account_id=equity_account_id, amount_cents=initial_balance_cents, posting_type="DEBIT", ownership_scope=ownership_scope))

                        postings.append(Posting(id=generate_uuid(), transaction_id=tx_id, account_id=account.id, amount_cents=initial_balance_cents, posting_type="CREDIT", ownership_scope=ownership_scope))

                    cursor.execute("""

                    INSERT INTO transactions (id, tx_date, tx_type, description, created_by_member_id, idempotency_key, is_voided, created_at)

                    VALUES (?, ?, 'ADJUSTMENT', ?, ?, ?, 0, ?)

                    """, (tx_id, tx_date, f"Начальный остаток счета '{account.name}'", owner_member_id, f"init_bal_{account.id}", current_iso_time()))

                    for p in postings:

                        cursor.execute("""

                        INSERT INTO postings (id, transaction_id, account_id, amount_cents, posting_type, ownership_scope, purpose_allocation, note, created_at)

                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)

                        """, (p.id, tx_id, p.account_id, p.amount_cents, p.posting_type, p.ownership_scope, p.purpose_allocation, p.note, current_iso_time()))

            # Record CDC event for Account Creation

            acc_payload = {

                "id": account.id,

                "code": account.code,

                "name": account.name,

                "account_type": account.account_type,

                "subtype": account.subtype,

                "currency": account.currency,

                "ownership_scope": account.ownership_scope,

                "owner_member_id": account.owner_member_id,

                "description": account.description,

                "credit_limit_cents": account.credit_limit_cents,

                "initial_balance_cents": account.initial_balance_cents,

                "is_active": 1

            }

            self._get_sync_engine().record_change_event("ACCOUNT", account.id, "INSERT", acc_payload, cursor=cursor)
            if initial_balance_cents > 0:
                self._get_sync_engine().record_change_event("TRANSACTION", tx_id, "INSERT",
                    self._transaction_snapshot(cursor, tx_id), cursor=cursor)

            self._commit(conn)

            self._save_if_encrypted()

            return account

        finally:

            self._close_if_local(conn)

    @atomic_operation
    def update_account(

        self,

        account_id: str,

        name: Optional[str] = None,

        description: Optional[str] = None,

        credit_limit_cents: Optional[int] = None,

        ownership_scope: Optional[str] = None

    ) -> bool:

        """Update account properties."""

        conn = self._get_conn()

        cursor = conn.cursor()

        try:

            updates = []

            params = []

            if name is not None:

                updates.append("name = ?")

                params.append(name.strip())

            if description is not None:

                updates.append("description = ?")

                params.append(description.strip())

            if credit_limit_cents is not None:

                require_cents(credit_limit_cents, allow_zero=True)

                if credit_limit_cents < 0:

                    raise ValueError("Кредитный лимит не может быть отрицательным.")

                updates.append("credit_limit_cents = ?")

                params.append(credit_limit_cents)

            if ownership_scope is not None:

                updates.append("ownership_scope = ?")

                params.append(ownership_scope)

            if not updates:

                return True

            params.append(account_id)

            query = f"UPDATE accounts SET {', '.join(updates)} WHERE id = ?;"

            cursor.execute(query, tuple(params))

            if cursor.rowcount > 0:

                cursor.execute("SELECT id, code, name, account_type, subtype, currency, ownership_scope, owner_member_id, description, credit_limit_cents, initial_balance_cents, is_active FROM accounts WHERE id = ?;", (account_id,))

                a_row = cursor.fetchone()

                if a_row:

                    self._get_sync_engine().record_change_event("ACCOUNT", account_id, "UPDATE", dict(a_row), cursor=cursor)

            self._commit(conn)

            self._save_if_encrypted()

            return cursor.rowcount > 0

        finally:

            self._close_if_local(conn)

    @atomic_operation
    def archive_account(self, account_id: str) -> bool:

        """Soft-archive account by setting is_active = 0."""

        if self.get_account_balance_cents(account_id) != 0:
            raise ValueError("Перед закрытием счёта переведите его остаток: баланс должен быть нулевым.")
        conn = self._get_conn()

        cursor = conn.cursor()

        try:

            cursor.execute("UPDATE accounts SET is_active = 0 WHERE id = ?", (account_id,))

            if cursor.rowcount > 0:

                self._get_sync_engine().record_change_event("ACCOUNT", account_id, "UPDATE", {"id": account_id, "is_active": 0}, cursor=cursor)

            self._commit(conn)

            self._save_if_encrypted()

            return cursor.rowcount > 0

        finally:

            self._close_if_local(conn)

    @atomic_operation
    def void_transaction(self, transaction_id: str, reason: str = "Аннулирование операции") -> bool:

        """

        Mark transaction as voided. Preserves immutable audit trail.

        """

        conn = self._get_conn()

        cursor = conn.cursor()

        try:

            cursor.execute("UPDATE transactions SET is_voided = 1, voided_reason = ? WHERE id = ?;", (reason, transaction_id))

            if cursor.rowcount > 0:

                self._get_sync_engine().record_change_event(

                    "TRANSACTION", transaction_id, "VOID",

                    {"id": transaction_id, "voided_reason": reason},

                    cursor=cursor

                )

                self._commit(conn)

                self._save_if_encrypted()

                return True

            return False

        finally:

            self._close_if_local(conn)

    @atomic_operation
    def update_transaction(self, transaction_id: str, tx_date: str = None,
                           description: str = None, amount_cents: int = None,
                           category_id: str = None, account_id: str = None,
                           tx_type: str = None) -> bool:
        """Edit a simple journal entry without inventing a split allocation rule."""
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM transactions WHERE id = ? AND is_voided = 0", (transaction_id,))
        old = cursor.fetchone()
        if old is None:
            return False
        if tx_date is not None:
            date.fromisoformat(tx_date)
        if amount_cents is not None:
            require_cents(amount_cents)
        if tx_type is not None and tx_type != old["tx_type"]:
            raise ValueError("Изменение типа существующей операции запрещено. Отмените её и создайте новую.")
        cursor.execute("SELECT p.*,a.account_type,a.currency FROM postings p JOIN accounts a ON a.id=p.account_id WHERE p.transaction_id=?", (transaction_id,))
        postings = [dict(row) for row in cursor.fetchall()]
        if len(postings) != 2 and any(v is not None for v in (amount_cents,category_id,account_id)):
            raise ValueError("Составную операцию можно изменить только явным распределением проводок. Отмените её и создайте новую.")
        category_account = None
        if category_id:
            cursor.execute("SELECT category_type FROM categories WHERE id=? AND is_active=1", (category_id,))
            category = cursor.fetchone()
            expected_category = "EXPENSE" if old["tx_type"] == "CREDIT_PURCHASE" else old["tx_type"]
            if category is None or category["category_type"] != expected_category:
                raise ValueError("Категория не соответствует типу операции.")
            cursor.execute("SELECT id FROM accounts WHERE code=?", ("5010" if category["category_type"]=="EXPENSE" else "4010",))
            category_account = cursor.fetchone()["id"]
        if account_id:
            cursor.execute("SELECT account_type,currency,is_active FROM accounts WHERE id=?", (account_id,))
            target = cursor.fetchone()
            if target is None or target["account_type"] not in ("ASSET","LIABILITY") or not target["is_active"]:
                raise ValueError("Выбранный финансовый счёт не найден или закрыт.")
            old_currencies = {p["currency"] for p in postings if p["account_type"] in ("ASSET","LIABILITY")}
            if old_currencies and target["currency"] not in old_currencies:
                raise ValueError("Изменение валюты операции без обмена не поддерживается.")
            if old["tx_type"] not in ("INCOME","EXPENSE","CREDIT_PURCHASE"):
                raise ValueError("Для изменения счёта этой операции используйте отмену и новую операцию.")
        for post in postings:
            if amount_cents is not None:
                post["amount_cents"] = amount_cents
            if post["account_type"] in ("ASSET","LIABILITY") and account_id:
                post["account_id"] = account_id
            if post["account_type"] in ("INCOME","EXPENSE") and category_id:
                post["account_id"] = category_account
                post["category_id"] = category_id
        debits = sum(p["amount_cents"] for p in postings if p["posting_type"]=="DEBIT")
        credits = sum(p["amount_cents"] for p in postings if p["posting_type"]=="CREDIT")
        if debits != credits or debits <= 0:
            raise ValueError("Нарушено равенство дебета и кредита.")
        cursor.execute("UPDATE transactions SET tx_date=?,description=? WHERE id=?", (tx_date or old["tx_date"], description if description is not None else old["description"], transaction_id))
        for post in postings:
            cursor.execute("UPDATE postings SET account_id=?,amount_cents=?,category_id=? WHERE id=?", (post["account_id"],post["amount_cents"],post.get("category_id"),post["id"]))
        payload=self._transaction_snapshot(cursor,transaction_id)
        updated=Transaction(id=transaction_id,tx_date=payload["tx_date"],tx_type=payload["tx_type"],description=payload["description"],created_by_member_id=payload.get("created_by_member_id"),postings=[Posting(id=p["id"],transaction_id=transaction_id,account_id=p["account_id"],amount_cents=p["amount_cents"],posting_type=p["posting_type"],ownership_scope=p["ownership_scope"],purpose_allocation=p["purpose_allocation"],category_id=p.get("category_id")) for p in payload["postings"]])
        payload["payload_hash"]=compute_tx_payload_hash(updated)
        cursor.execute("UPDATE transactions SET payload_hash=? WHERE id=?",(payload["payload_hash"],transaction_id))
        self._get_sync_engine().record_change_event("TRANSACTION",transaction_id,"UPDATE",payload,cursor=cursor)
        return True

    def get_account_by_code(self, code: str) -> Optional[Account]:

        """Fetch account by unique accounting code."""

        conn = self._get_conn()

        cursor = conn.cursor()

        cursor.execute("SELECT * FROM accounts WHERE code = ?", (code,))

        row = cursor.fetchone()

        self._close_if_local(conn)

        if not row:

            return None

        return Account(

            id=row["id"],

            code=row["code"],

            name=row["name"],

            account_type=row["account_type"],

            subtype=row["subtype"],

            currency=row["currency"],

            ownership_scope=row["ownership_scope"],

            owner_member_id=row["owner_member_id"],

            description=row["description"],

            credit_limit_cents=row["credit_limit_cents"] if "credit_limit_cents" in row.keys() else 0,

            initial_balance_cents=row["initial_balance_cents"] if "initial_balance_cents" in row.keys() else 0,

            is_active=bool(row["is_active"]),

            created_at=row["created_at"]

        )

    def get_account_by_id(self, account_id: str) -> Optional[Account]:

        """Fetch account by its UUID."""

        conn = self._get_conn()

        cursor = conn.cursor()

        cursor.execute("SELECT * FROM accounts WHERE id = ?", (account_id,))

        row = cursor.fetchone()

        self._close_if_local(conn)

        if not row:

            return None

        return Account(

            id=row["id"],

            code=row["code"],

            name=row["name"],

            account_type=row["account_type"],

            subtype=row["subtype"],

            currency=row["currency"],

            ownership_scope=row["ownership_scope"],

            owner_member_id=row["owner_member_id"],

            description=row["description"],

            credit_limit_cents=row["credit_limit_cents"] if "credit_limit_cents" in row.keys() else 0,

            initial_balance_cents=row["initial_balance_cents"] if "initial_balance_cents" in row.keys() else 0,

            is_active=bool(row["is_active"]),

            created_at=row["created_at"]

        )

    get_account = get_account_by_id

    # ---------------------------------------------------------

    # 2. Financial Transactions & Idempotency

    # ---------------------------------------------------------

    @atomic_operation
    def record_transaction(self, tx: Transaction, idempotency_key: Optional[str] = None) -> str:

        """

        Record a financial transaction with postings inside an atomic SQLite transaction.

        Enforces double-entry equation (Debit == Credit) and checks idempotency payload matching.

        """

        date.fromisoformat(tx.tx_date)
        for p in tx.postings:
            require_cents(p.amount_cents)
            if p.posting_type not in ("DEBIT", "CREDIT"):
                raise ValueError("Недопустимое направление проводки.")
        if not tx.validate_double_entry():

            debits = sum(p.amount_cents for p in tx.postings if p.posting_type == "DEBIT")

            credits = sum(p.amount_cents for p in tx.postings if p.posting_type == "CREDIT")

            raise ValueError(f"Double-entry balance check failed! Total Debits: {debits} cents != Total Credits: {credits} cents")

        conn = self._get_conn()

        cursor = conn.cursor()
        # Hash exactly the normalized payload that will be persisted and replicated.
        if tx.created_by_member_id:
            cursor.execute("SELECT id FROM members WHERE id=?", (str(tx.created_by_member_id).strip(),))
            if cursor.fetchone() is None:
                tx.created_by_member_id = None
        for posting in tx.postings:
            if posting.category_id:
                cursor.execute("SELECT id FROM categories WHERE id=?", (str(posting.category_id).strip(),))
                if cursor.fetchone() is None:
                    posting.category_id = None
        payload_hash = compute_tx_payload_hash(tx)

        # Idempotency check with payload verification

        if idempotency_key:

            cursor.execute("SELECT id, payload_hash FROM transactions WHERE idempotency_key = ?", (idempotency_key,))

            existing = cursor.fetchone()

            if existing:

                existing_hash = existing["payload_hash"]

                if not existing_hash or not existing_hash.startswith("v2:"):
                    existing_payload = self._transaction_snapshot(cursor, existing["id"])
                    old_tx = Transaction(id=existing["id"], tx_date=existing_payload["tx_date"],
                        tx_type=existing_payload["tx_type"], description=existing_payload["description"],
                        created_by_member_id=existing_payload.get("created_by_member_id"),
                        postings=[Posting(id=p["id"], transaction_id=existing["id"], account_id=p["account_id"],
                            amount_cents=p["amount_cents"], posting_type=p["posting_type"],
                            ownership_scope=p["ownership_scope"], purpose_allocation=p["purpose_allocation"],
                            category_id=p.get("category_id")) for p in existing_payload["postings"]])
                    existing_hash = compute_tx_payload_hash(old_tx)
                if existing_hash and existing_hash != payload_hash:

                    self._close_if_local(conn)

                    raise ValueError(

                        f"Конфликт идемпотентности: ключ '{idempotency_key}' уже зарегистрирован "

                        "с другими параметрами операции. Изменение содержимого запрещено."

                    )

                self._close_if_local(conn)

                return existing["id"]

        try:

            financial_currencies = set()
            for p in tx.postings:
                cursor.execute("SELECT account_type,currency,is_active FROM accounts WHERE id = ?", (p.account_id,))
                acc = cursor.fetchone()
                if acc is None or not acc["is_active"]:
                    raise ValueError("Счёт проводки не найден или закрыт.")
                if acc["account_type"] in ("ASSET", "LIABILITY"):
                    financial_currencies.add(acc["currency"])
            if len(financial_currencies) > 1:
                raise ValueError("Межвалютная операция требует отдельной модели обмена и курса.")

            # Sanitize created_by_member_id to prevent FOREIGN KEY constraint failed
            created_by = tx.created_by_member_id
            if created_by:
                created_by = str(created_by).strip()
                cursor.execute("SELECT id FROM members WHERE id = ?;", (created_by,))
                if not cursor.fetchone():
                    created_by = None
            else:
                created_by = None

            # 1. Insert Transaction Header

            cursor.execute("""

            INSERT INTO transactions 

            (id, tx_date, tx_type, description, created_by_member_id, idempotency_key, payload_hash, is_voided, created_at)

            VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)

            """, (tx.id, tx.tx_date, tx.tx_type, tx.description, created_by, idempotency_key, payload_hash, tx.created_at))

            # 2. Insert Postings

            for p in tx.postings:

                p_cat_id = getattr(p, "category_id", None)
                if p_cat_id:
                    p_cat_id = str(p_cat_id).strip()
                    cursor.execute("SELECT id FROM categories WHERE id = ?;", (p_cat_id,))
                    if not cursor.fetchone():
                        p_cat_id = None
                else:
                    p_cat_id = None

                cursor.execute("""

                INSERT INTO postings 

                (id, transaction_id, account_id, amount_cents, posting_type, ownership_scope, purpose_allocation, note, category_id, created_at)

                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)

                """, (p.id, tx.id, p.account_id, p.amount_cents, p.posting_type, p.ownership_scope, p.purpose_allocation, p.note, p_cat_id, current_iso_time()))

            # 3. Log change for peer sync with full transaction snapshot

            tx_payload = {

                "id": tx.id,

                "tx_date": tx.tx_date,

                "tx_type": tx.tx_type,

                "description": tx.description,

                "created_by_member_id": created_by,

                "idempotency_key": idempotency_key,

                "payload_hash": payload_hash,

                "is_voided": 0,

                "voided_reason": None,

                "reversal_of_id": tx.reversal_of_id,

                "created_at": tx.created_at,

                "postings": [

                    {

                        "id": p.id,

                        "account_id": p.account_id,

                        "amount_cents": p.amount_cents,

                        "posting_type": p.posting_type,

                        "ownership_scope": p.ownership_scope,

                        "purpose_allocation": p.purpose_allocation,

                        "category_id": getattr(p, "category_id", None),

                        "note": p.note,

                        "created_at": getattr(p, "created_at", current_iso_time())

                    }

                    for p in tx.postings

                ]

            }

            self._get_sync_engine().record_change_event("TRANSACTION", tx.id, "INSERT", tx_payload, cursor=cursor)

            self._commit(conn)

            self._save_if_encrypted()

            return tx.id

        except sqlite3.IntegrityError as e:

            if not self._atomic_depth:
                conn.rollback()

            # If concurrent race condition triggered UNIQUE constraint on idempotency_key:

            if "transactions.idempotency_key" in str(e) and idempotency_key:

                cursor.execute("SELECT id,payload_hash FROM transactions WHERE idempotency_key = ?", (idempotency_key,))

                winner = cursor.fetchone()

                if winner:
                    if winner["payload_hash"] == payload_hash:
                        return winner["id"]
                    raise ValueError("Конфликт идемпотентности при конкурентной записи.") from e

            raise e

        except Exception as e:

            if not self._atomic_depth:
                conn.rollback()

            raise e

        finally:

            self._close_if_local(conn)

    # ---------------------------------------------------------

    # 3. Internal Transfers (Stage 2 Requirement 4.3)

    # ---------------------------------------------------------

    @atomic_operation
    def record_transfer(

        self,

        from_account_id: str,

        to_account_id: str,

        amount_cents: int,

        description: str = "Внутренний перевод",

        tx_date: Optional[str] = None,

        created_by_member_id: Optional[str] = None,

        idempotency_key: Optional[str] = None

    ) -> str:

        """

        Record an atomic internal transfer between accounts.

        Rules:

        - Transfers are NEITHER income NOR expense.

        - Source is CREDITED, Destination is DEBITED.

        - History retains references to both accounts.

        """

        if from_account_id == to_account_id:

            raise ValueError("Счет списания и счет зачисления не могут совпадать.")

        require_cents(amount_cents)
        if amount_cents <= 0:

            raise ValueError("Сумма перевода должна быть строго больше нуля.")

        from_acc = self.get_account_by_id(from_account_id)

        to_acc = self.get_account_by_id(to_account_id)

        if not from_acc:

            raise ValueError(f"Счет списания {from_account_id} не найден.")

        if not to_acc:

            raise ValueError(f"Счет зачисления {to_account_id} не найден.")
        if from_acc.currency != to_acc.currency:
            raise ValueError("Межвалютный перевод без курса не поддерживается.")

        tx_id = ("transfer-v2:" + hashlib.sha256(str(idempotency_key).encode("utf-8")).hexdigest()) if idempotency_key else generate_uuid()

        date_str = tx_date or current_iso_time()[:10]

        postings = [

            # CREDIT source account

            Posting(

                id=generate_uuid(),

                transaction_id=tx_id,

                account_id=from_acc.id,

                amount_cents=amount_cents,

                posting_type="CREDIT",

                ownership_scope=from_acc.ownership_scope,

                purpose_allocation="SAFE_TO_SPEND",

                note=f"Перевод на '{to_acc.name}'"

            ),

            # DEBIT destination account

            Posting(

                id=generate_uuid(),

                transaction_id=tx_id,

                account_id=to_acc.id,

                amount_cents=amount_cents,

                posting_type="DEBIT",

                ownership_scope=to_acc.ownership_scope,

                purpose_allocation="SAFE_TO_SPEND",

                note=f"Перевод с '{from_acc.name}'"

            )

        ]

        tx = Transaction(

            id=tx_id,

            tx_date=date_str,

            tx_type="TRANSFER",

            description=description,

            created_by_member_id=created_by_member_id,

            postings=postings

        )

        return self.record_transaction(tx, idempotency_key=idempotency_key)

    # ---------------------------------------------------------

    # 4. Personal Card for Common Expense (Stage 2 Requirement 4.5)

    # ---------------------------------------------------------

    def record_common_expense_from_personal_card(

        self,

        personal_account_id: str,

        category_account_id: str,

        amount_cents: int,

        description: str,

        member_id: Optional[str] = None,

        tx_date: Optional[str] = None,

        idempotency_key: Optional[str] = None

    ) -> str:

        """

        Record a common family expense paid from an individual member's personal card.

        Rule:

        - Does NOT automatically create any debt or loan obligation.

        - Distinctly attributes the personal paying account and common expense category.

        """

        if amount_cents <= 0:

            raise ValueError("Сумма расхода должна быть больше нуля.")

        personal_acc = self.get_account_by_id(personal_account_id)

        if not personal_acc:

            raise ValueError(f"Личный счет {personal_account_id} не найден.")

        cat_acc = self.get_account_by_id(category_account_id)

        if not cat_acc or cat_acc.account_type != "EXPENSE":

            raise ValueError(f"Категория расхода {category_account_id} не найдена или не является расходной статьей.")

        tx_id = generate_uuid()

        date_str = tx_date or current_iso_time()[:10]

        postings = [

            # DEBIT Expense (Common family budget consumption)

            Posting(

                id=generate_uuid(),

                transaction_id=tx_id,

                account_id=cat_acc.id,

                amount_cents=amount_cents,

                posting_type="DEBIT",

                ownership_scope="COMMON",

                purpose_allocation="SAFE_TO_SPEND",

                note=f"Расход семьи: '{personal_acc.name}'"

            ),

            # CREDIT Paying Account (Reduction of family cash/bank asset)

            Posting(

                id=generate_uuid(),

                transaction_id=tx_id,

                account_id=personal_acc.id,

                amount_cents=amount_cents,

                posting_type="CREDIT",

                ownership_scope="COMMON",

                purpose_allocation="SAFE_TO_SPEND",

                note=f"Оплата: '{description}'"

            )

        ]

        tx = Transaction(

            id=tx_id,

            tx_date=date_str,

            tx_type="EXPENSE",

            description=description,

            created_by_member_id=member_id,

            postings=postings

        )

        return self.record_transaction(tx, idempotency_key=idempotency_key)

    # ---------------------------------------------------------

    # 5. Balances & Financial Overview (Stage 2 Requirement 4.6)

    # ---------------------------------------------------------

    def get_account_balance_cents(self, account_id: str) -> int:

        """

        Calculate account balance in integer cents from all non-voided postings.

        For ASSET / EXPENSE: Balance = Debits - Credits

        For LIABILITY / EQUITY / INCOME: Balance = Credits - Debits

        """

        conn = self._get_conn()

        cursor = conn.cursor()

        cursor.execute("SELECT account_type FROM accounts WHERE id = ?", (account_id,))

        acc_row = cursor.fetchone()

        if not acc_row:

            self._close_if_local(conn)

            raise ValueError(f"Account {account_id} not found")

        acc_type = acc_row["account_type"]

        cursor.execute("""

        SELECT 

            COALESCE(SUM(CASE WHEN p.posting_type = 'DEBIT' THEN p.amount_cents ELSE 0 END), 0) AS total_debit,

            COALESCE(SUM(CASE WHEN p.posting_type = 'CREDIT' THEN p.amount_cents ELSE 0 END), 0) AS total_credit

        FROM postings p

        JOIN transactions t ON p.transaction_id = t.id

        WHERE p.account_id = ? AND t.is_voided = 0

        """, (account_id,))

        res = cursor.fetchone()

        debits = res["total_debit"]

        credits = res["total_credit"]

        self._close_if_local(conn)

        if acc_type in ("ASSET", "EXPENSE"):

            return debits - credits

        else:

            return credits - debits

    def get_financial_overview(self) -> Dict[str, Any]:

        """

        Generate complete multidimensional family financial overview:

        - Common Liquid Assets (All family cards + cash in a unified pool)

        - Safe-to-Spend (Liquid Assets minus Credit Debt minus Upcoming Obligations)

        - Deficit Flag & Deficit Amount (if liquid assets < debt)

        - Emergency Reserves (Savings + Deposits)

        - Loan & Mortgage Debt

        - Family Net Worth (Total Assets - Total Liabilities)

        - Informational cardholder balances (Husband / Wife cards)

        - Credit Cards Summary (Limit, Debt, Available)

        """

        conn = self._get_conn()

        cursor = conn.cursor()

        cursor.execute("""

        SELECT 

            a.id, a.code, a.name, a.account_type, a.subtype, a.currency, a.ownership_scope, a.owner_member_id, a.credit_limit_cents, a.is_active,

            COALESCE(SUM(CASE WHEN t.id IS NOT NULL AND p.posting_type = 'DEBIT' THEN p.amount_cents ELSE 0 END), 0) AS total_debit,

            COALESCE(SUM(CASE WHEN t.id IS NOT NULL AND p.posting_type = 'CREDIT' THEN p.amount_cents ELSE 0 END), 0) AS total_credit

        FROM accounts a

        LEFT JOIN postings p ON a.id = p.account_id

        LEFT JOIN transactions t ON p.transaction_id = t.id AND t.is_voided = 0

        WHERE a.is_active = 1

        GROUP BY a.id

        ORDER BY a.code

        """)

        rows = cursor.fetchall()

        self._close_if_local(conn)

        common_liquid_cents = 0

        emergency_reserves_cents = 0

        credit_debt_cents = 0

        total_credit_limit_cents = 0

        loans_debt_cents = 0

        husband_cents = 0

        wife_cents = 0

        total_assets_cents = 0

        total_liabilities_cents = 0

        accounts_list = []
        by_currency = {}

        for r in rows:

            acc_type = r["account_type"]

            subtype = r["subtype"]

            scope = r["ownership_scope"]

            limit = r["credit_limit_cents"] or 0

            debit = r["total_debit"]

            credit = r["total_credit"]

            bal = (debit - credit) if acc_type in ("ASSET", "EXPENSE") else (credit - debit)

            currency=r["currency"]
            totals=by_currency.setdefault(currency,{"assets_cents":0,"liabilities_cents":0,"liquid_cents":0,"net_worth_cents":0})
            if acc_type == "ASSET":
                totals["assets_cents"] += bal
                if subtype in ("DEBIT_CARD","CASH","CHECKING","SAVINGS_LIQUID"):
                    totals["liquid_cents"] += bal
            elif acc_type == "LIABILITY":
                totals["liabilities_cents"] += bal
            totals["net_worth_cents"]=totals["assets_cents"]-totals["liabilities_cents"]
            native_bal=bal
            # Compatibility totals are explicitly RUB-only; native rows are retained below.
            if currency != "RUB":
                bal=0
                limit=0
            # Assets

            if acc_type == "ASSET":

                total_assets_cents += bal

                # 1. Family Liquid Assets: ALL debit cards, cash, and checking accounts

                if subtype in ("DEBIT_CARD", "CASH", "CHECKING", "SAVINGS_LIQUID"):

                    common_liquid_cents += bal

                # 2. Long-term Emergency Reserves: savings, deposits, reserves

                elif subtype in ("SAVINGS", "DEPOSIT", "RESERVE"):

                    emergency_reserves_cents += bal

                # Informational breakdown by member cards (not separate budgets)

                if scope == "PERSONAL_HUSBAND" or r["code"] == "1011":

                    husband_cents += bal

                elif scope == "PERSONAL_WIFE" or r["code"] == "1012":

                    wife_cents += bal

            # Liabilities

            elif acc_type == "LIABILITY":

                # Preserve signed historic overpayments; only RUB enters legacy totals.
                total_liabilities_cents += bal

                if subtype == "CREDIT_CARD":

                    debt = max(0, bal)

                    credit_debt_cents += debt

                    total_credit_limit_cents += limit


                elif subtype in ("LOAN", "MORTGAGE", "CONSUMER_LOAN", "AUTO_LOAN", "PERSONAL_DEBT", "INSTALLMENT_BNPL"):

                    loan_debt = max(0, bal)

                    loans_debt_cents += loan_debt


            accounts_list.append({

                "id": r["id"],

                "code": r["code"],

                "name": r["name"],

                "type": acc_type,

                "subtype": subtype,

                "scope": scope,

                "owner_member_id": r["owner_member_id"],

                "balance_cents": native_bal,

                "balance_rub": cents_to_rubles(native_bal),

                "currency": r["currency"],

                "credit_limit_cents": r["credit_limit_cents"] or 0,

                "credit_limit_rub": cents_to_rubles(r["credit_limit_cents"] or 0)

            })

        # Net Safe-to-Spend calculation (includes unpaid monthly obligations)

        unpaid_obl_cents, total_obl_cents, paid_obl_cents = self.calculate_unpaid_obligations_cents()

        net_safe_to_spend_cents = common_liquid_cents - credit_debt_cents - unpaid_obl_cents

        is_deficit = net_safe_to_spend_cents < 0

        deficit_cents = abs(net_safe_to_spend_cents) if is_deficit else 0

        safe_to_spend_cents = max(0, net_safe_to_spend_cents)

        available_credit_cents = max(0, total_credit_limit_cents - credit_debt_cents)

        net_worth_cents = total_assets_cents - total_liabilities_cents

        return {
            "base_currency": "RUB",
            "totals_scope": "RUB_ONLY",
            "by_currency": by_currency,
            "non_base_excluded": sorted(c for c in by_currency if c != "RUB"),

            "common_liquid_assets_cents": common_liquid_cents,

            "common_liquid_assets_rub": cents_to_rubles(common_liquid_cents),

            "common_safe_to_spend_cents": safe_to_spend_cents,

            "common_safe_to_spend_rub": cents_to_rubles(safe_to_spend_cents),

            "net_safe_to_spend_cents": net_safe_to_spend_cents,

            "net_safe_to_spend_rub": cents_to_rubles(net_safe_to_spend_cents),

            "is_deficit": is_deficit,

            "deficit_cents": deficit_cents,

            "deficit_rub": cents_to_rubles(deficit_cents),

            "emergency_reserves_cents": emergency_reserves_cents,

            "emergency_reserves_rub": cents_to_rubles(emergency_reserves_cents),

            "loans_debt_cents": loans_debt_cents,

            "loans_debt_rub": cents_to_rubles(loans_debt_cents),

            "unpaid_obligations_cents": unpaid_obl_cents,

            "unpaid_obligations_rub": cents_to_rubles(unpaid_obl_cents),

            "total_obligations_cents": total_obl_cents,

            "total_obligations_rub": cents_to_rubles(total_obl_cents),

            "paid_obligations_cents": paid_obl_cents,

            "paid_obligations_rub": cents_to_rubles(paid_obl_cents),

            "family_net_worth_cents": net_worth_cents,

            "family_net_worth_rub": cents_to_rubles(net_worth_cents),

            "husband_personal_balance_cents": husband_cents,

            "husband_personal_balance_rub": cents_to_rubles(husband_cents),

            "wife_personal_balance_cents": wife_cents,

            "wife_personal_balance_rub": cents_to_rubles(wife_cents),

            "credit_cards": {

                "total_limit_cents": total_credit_limit_cents,

                "total_limit_rub": cents_to_rubles(total_credit_limit_cents),

                "total_debt_cents": credit_debt_cents,

                "total_debt_rub": cents_to_rubles(credit_debt_cents),

                "available_limit_cents": available_credit_cents,

                "available_limit_rub": cents_to_rubles(available_credit_cents)

            },

            "accounts": accounts_list

        }

    def calculate_safe_to_spend_cents(self) -> Dict[str, Any]:

        """Compatibility method for existing endpoints."""

        overview = self.get_financial_overview()

        return {

            "common_liquid_assets_cents": overview["common_liquid_assets_cents"],

            "emergency_reserve_cents": overview["emergency_reserves_cents"],

            "credit_card_debt_cents": overview["credit_cards"]["total_debt_cents"],

            "unpaid_obligations_cents": overview["unpaid_obligations_cents"],

            "common_safe_to_spend_cents": overview["common_safe_to_spend_cents"],

            "net_safe_to_spend_cents": overview["net_safe_to_spend_cents"],

            "is_deficit": overview["is_deficit"],

            "deficit_cents": overview["deficit_cents"]

        }

    # ---------------------------------------------------------

    # 6. Hierarchical Category Tree (Stage 3 Requirement 1)

    # ---------------------------------------------------------

    def seed_default_categories(self) -> List[str]:
        """
        Seed pre-defined hierarchical category tree for a Russian family.
        Does not overwrite if categories already exist.
        """
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM categories;")
        existing_ids = {row[0] for row in cursor.fetchall()}

        categories = [
            # EXPENSES
            # (id, name, type, parent_id, icon, sort_order)
            ("cat_food", "Продукты и питание", "EXPENSE", None, "🛒", 10),
            ("cat_food_super", "Супермаркеты и продукты", "EXPENSE", "cat_food", "🛍️", 11),
            ("cat_food_cafe", "Кафе, рестораны и фастфуд", "EXPENSE", "cat_food", "☕", 12),
            ("cat_food_delivery", "Доставка готовой еды", "EXPENSE", "cat_food", "🛵", 13),
            ("cat_housing", "Жилье и связь", "EXPENSE", None, "🏠", 20),
            ("cat_housing_rent", "Аренда / Ипотека", "EXPENSE", "cat_housing", "🔑", 21),
            ("cat_housing_communal", "ЖКХ и коммунальные услуги", "EXPENSE", "cat_housing", "⚡", 22),
            ("cat_housing_comm", "Интернет и мобильная связь", "EXPENSE", "cat_housing", "📶", 23),
            ("cat_housing_goods", "Товары для дома и уют", "EXPENSE", "cat_housing", "🛋️", 24),
            ("cat_housing_repair", "Ремонт и стройматериалы", "EXPENSE", "cat_housing", "🔨", 25),
            ("cat_transport", "Транспорт и авто", "EXPENSE", None, "🚗", 30),
            ("cat_transport_fuel", "Бензин и заправки", "EXPENSE", "cat_transport", "⛽", 31),
            ("cat_transport_taxi", "Такси и каршеринг", "EXPENSE", "cat_transport", "🚕", 32),
            ("cat_transport_public", "Общественный транспорт", "EXPENSE", "cat_transport", "🚌", 33),
            ("cat_transport_service", "ТО, страховка, парковка", "EXPENSE", "cat_transport", "🛡️", 34),
            ("cat_health", "Здоровье и медицина", "EXPENSE", None, "💊", 40),
            ("cat_health_pharmacy", "Аптеки и лекарства", "EXPENSE", "cat_health", "🩹", 41),
            ("cat_health_doctors", "Врачи, клиники и анализы", "EXPENSE", "cat_health", "🩺", 42),
            ("cat_health_dentist", "Стоматология", "EXPENSE", "cat_health", "🦷", 43),
            ("cat_kids", "Дети и развитие", "EXPENSE", None, "👶", 50),
            ("cat_kids_edu", "Школа, садик, кружки, репетиторы", "EXPENSE", "cat_kids", "📚", 51),
            ("cat_kids_clothes", "Детская одежда и обувь", "EXPENSE", "cat_kids", "👕", 52),
            ("cat_kids_toys", "Игрушки, секции и досуг", "EXPENSE", "cat_kids", "🧸", 53),
            ("cat_leisure", "Досуг, отдых и подписки", "EXPENSE", None, "🎉", 60),
            ("cat_leisure_events", "Кино, театры, концерты, хобби", "EXPENSE", "cat_leisure", "🎟️", 61),
            ("cat_leisure_travel", "Путешествия, отели и билеты", "EXPENSE", "cat_leisure", "✈️", 62),
            ("cat_leisure_subs", "Цифровые подписки и сервисы", "EXPENSE", "cat_leisure", "📱", 63),
            ("cat_personal", "Личные траты и одежда", "EXPENSE", None, "👔", 70),
            ("cat_personal_clothes", "Одежда и обувь для взрослых", "EXPENSE", "cat_personal", "👗", 71),
            ("cat_personal_care", "Стрижки, уход и косметика", "EXPENSE", "cat_personal", "✂️", 72),
            ("cat_personal_gifts", "Подарки близким и друзьям", "EXPENSE", "cat_personal", "🎁", 73),
            # DEBTS & LOANS (Кредиты, долги и займы)
            ("cat_debts", "Кредиты, долги и займы", "EXPENSE", None, "💳", 80),
            ("cat_debts_credit_card", "Погашение кредитных карт", "EXPENSE", "cat_debts", "💳", 81),
            ("cat_debts_consumer", "Потребительские кредиты", "EXPENSE", "cat_debts", "📋", 82),
            ("cat_debts_mortgage", "Ипотечные платежи", "EXPENSE", "cat_debts", "🏠", 83),
            ("cat_debts_auto", "Автокредиты", "EXPENSE", "cat_debts", "🚗", 84),
            ("cat_debts_bnpl", "Рассрочки и сплиты (BNPL)", "EXPENSE", "cat_debts", "🛍️", 85),
            ("cat_debts_personal", "Возврат долгов людям", "EXPENSE", "cat_debts", "🤝", 86),
            ("cat_debts_interest", "Проценты, штрафы и комиссии", "EXPENSE", "cat_debts", "⚠️", 87),
            ("cat_other_exp", "Прочие расходы", "EXPENSE", None, "📦", 90),
            # INCOME
            ("cat_salary", "Зарплата и аванс", "INCOME", None, "💼", 10),
            ("cat_salary_husband", "Зарплата Муж", "INCOME", "cat_salary", "👨", 11),
            ("cat_salary_wife", "Зарплата Жена", "INCOME", "cat_salary", "👩", 12),
            ("cat_freelance", "Подработка и проекты", "INCOME", None, "💻", 20),
            ("cat_passive", "Пассивный доход", "INCOME", None, "📈", 30),
            ("cat_passive_interest", "Проценты по вкладам и счетам", "INCOME", "cat_passive", "💰", 31),
            ("cat_passive_cashback", "Кэшбэк и бонусы банков", "INCOME", "cat_passive", "💳", 32),
            ("cat_borrow_income", "Получение кредитов и займов", "INCOME", None, "📥", 35),
            ("cat_other_inc", "Подарки и прочие поступления", "INCOME", None, "🎁", 40),
        ]
        created_ids = []
        for cid, name, ctype, pid, icon, sort_order in categories:
            if cid not in existing_ids:
                cursor.execute("""
                INSERT OR IGNORE INTO categories (id, name, category_type, parent_id, icon, sort_order, is_active)
                VALUES (?, ?, ?, ?, ?, ?, 1);
                """, (cid, name, ctype, pid, icon, sort_order))
                created_ids.append(cid)
        conn.commit()
        self._save_if_encrypted()
        self._close_if_local(conn)
        return created_ids

    def create_category(self, name: str, category_type: str, parent_id: Optional[str] = None, icon: str = "tag", sort_order: int = 0) -> Category:

        """Create a new root category or subcategory."""

        cat_id = generate_uuid()

        conn = self._get_conn()

        cursor = conn.cursor()

        try:

            cursor.execute("""

            INSERT INTO categories (id, name, category_type, parent_id, icon, sort_order, is_active)

            VALUES (?, ?, ?, ?, ?, ?, 1);

            """, (cat_id, name.strip(), category_type, parent_id, icon, sort_order))

            cat_payload = {

                "id": cat_id,

                "name": name.strip(),

                "category_type": category_type,

                "parent_id": parent_id,

                "icon": icon,

                "sort_order": sort_order,

                "is_active": 1

            }

            self._get_sync_engine().record_change_event("CATEGORY", cat_id, "INSERT", cat_payload, cursor=cursor)

            self._commit(conn)

            self._save_if_encrypted()

            return Category(id=cat_id, name=name.strip(), category_type=category_type, parent_id=parent_id, icon=icon, sort_order=sort_order)

        finally:

            self._close_if_local(conn)

    def get_category_tree(self, category_type: Optional[str] = None) -> List[Dict[str, Any]]:

        """Return hierarchical category tree with subcategories."""

        conn = self._get_conn()

        cursor = conn.cursor()

        query = "SELECT id, name, category_type, parent_id, icon, sort_order, is_active FROM categories WHERE is_active = 1"

        params = []

        if category_type:

            query += " AND category_type = ?"

            params.append(category_type)

        query += " ORDER BY sort_order, name;"

        cursor.execute(query, tuple(params))

        rows = cursor.fetchall()

        self._close_if_local(conn)

        nodes = {}

        roots = []

        for r in rows:

            node = {

                "id": r["id"],

                "name": r["name"],

                "type": r["category_type"],

                "parent_id": r["parent_id"],

                "icon": r["icon"] or "tag",

                "sort_order": r["sort_order"],

                "subcategories": []

            }

            nodes[r["id"]] = node

        for r in rows:

            cid = r["id"]

            pid = r["parent_id"]

            if pid and pid in nodes:

                nodes[pid]["subcategories"].append(nodes[cid])

            else:

                roots.append(nodes[cid])

        return roots

    def get_flat_categories(self, category_type: Optional[str] = None) -> List[Dict[str, Any]]:

        """Return flat list of categories with parent_name for dropdowns and fast chips."""

        tree = self.get_category_tree(category_type)

        flat = []

        for root in tree:

            flat.append({

                "id": root["id"],

                "name": root["name"],

                "type": root["type"],

                "icon": root["icon"],

                "parent_id": None,

                "parent_name": None,

                "is_parent": len(root["subcategories"]) > 0

            })

            for sub in root["subcategories"]:

                flat.append({

                    "id": sub["id"],

                    "name": sub["name"],

                    "type": sub["type"],

                    "icon": sub["icon"],

                    "parent_id": root["id"],

                    "parent_name": root["name"],

                    "is_parent": False

                })

        return flat

    def update_category(self, category_id: str, name: Optional[str] = None, parent_id: Optional[str] = None, icon: Optional[str] = None, sort_order: Optional[int] = None) -> bool:

        """Update category properties."""

        conn = self._get_conn()

        cursor = conn.cursor()

        try:

            updates = []

            params = []

            if name is not None:

                updates.append("name = ?")

                params.append(name.strip())

            if parent_id is not None:

                updates.append("parent_id = ?")

                params.append(parent_id if parent_id != "" else None)

            if icon is not None:

                updates.append("icon = ?")

                params.append(icon)

            if sort_order is not None:

                updates.append("sort_order = ?")

                params.append(sort_order)

            if not updates:

                return True

            params.append(category_id)

            cursor.execute(f"UPDATE categories SET {', '.join(updates)} WHERE id = ?;", tuple(params))

            if cursor.rowcount > 0:

                cursor.execute("SELECT id, name, category_type, parent_id, icon, sort_order, is_active FROM categories WHERE id = ?;", (category_id,))

                c_row = cursor.fetchone()

                if c_row:

                    self._get_sync_engine().record_change_event("CATEGORY", category_id, "UPDATE", dict(c_row), cursor=cursor)

            self._commit(conn)

            self._save_if_encrypted()

            return cursor.rowcount > 0

        finally:

            self._close_if_local(conn)

    def archive_category(self, category_id: str) -> bool:

        """Soft-archive category."""

        conn = self._get_conn()

        cursor = conn.cursor()

        try:

            cursor.execute("UPDATE categories SET is_active = 0 WHERE id = ? OR parent_id = ?;", (category_id, category_id))

            if cursor.rowcount > 0:

                self._get_sync_engine().record_change_event("CATEGORY", category_id, "UPDATE", {"id": category_id, "is_active": 0}, cursor=cursor)

            self._commit(conn)

            self._save_if_encrypted()

            return cursor.rowcount > 0

        finally:

            self._close_if_local(conn)

    # ---------------------------------------------------------

    # 7. Fixed Obligations & Monthly Payment Tracking (Stage 3 Requirement 2)

    # ---------------------------------------------------------

    @atomic_operation
    def create_obligation(

        self,

        name: str,

        amount_cents: int,

        due_day: int,

        category_id: Optional[str] = None,

        payment_account_id: Optional[str] = None,

        note: Optional[str] = None

    ) -> Obligation:

        """Register a new recurring fixed obligation (rent, utilities, loan, subscription)."""

        require_cents(amount_cents)

        if type(due_day) is not int or not (1 <= due_day <= 31):

            raise ValueError("День списания должен быть от 1 до 31.")

        obl_id = generate_uuid()

        conn = self._get_conn()

        cursor = conn.cursor()


        # Sanitize foreign keys to prevent FOREIGN KEY constraint failed
        category_id = str(category_id).strip() if category_id else None
        if category_id:
            cursor.execute("SELECT id FROM categories WHERE id = ?;", (category_id,))
            if not cursor.fetchone():
                category_id = None
        else:
            category_id = None

        payment_account_id = str(payment_account_id).strip() if payment_account_id else None
        if payment_account_id:
            cursor.execute("SELECT id FROM accounts WHERE id = ?;", (payment_account_id,))
            if not cursor.fetchone():
                payment_account_id = None
        else:
            payment_account_id = None
        try:

            cursor.execute("""

            INSERT INTO obligations (id, name, amount_cents, due_day, category_id, payment_account_id, note, is_active)

            VALUES (?, ?, ?, ?, ?, ?, ?, 1);

            """, (obl_id, name.strip(), amount_cents, due_day, category_id, payment_account_id, note))

            obl_payload = {

                "id": obl_id,

                "name": name.strip(),

                "amount_cents": amount_cents,

                "due_day": due_day,

                "category_id": category_id,

                "payment_account_id": payment_account_id,

                "note": note,

                "is_active": 1

            }

            self._get_sync_engine().record_change_event("OBLIGATION", obl_id, "INSERT", obl_payload, cursor=cursor)

            self._commit(conn)

            self._save_if_encrypted()

            return Obligation(id=obl_id, name=name.strip(), amount_cents=amount_cents, due_day=due_day, category_id=category_id, payment_account_id=payment_account_id, note=note)

        finally:

            self._close_if_local(conn)

    @atomic_operation
    def update_obligation(

        self,

        obligation_id: str,

        name: Optional[str] = None,

        amount_cents: Optional[int] = None,

        due_day: Optional[int] = None,

        category_id: Optional[str] = None,

        payment_account_id: Optional[str] = None,

        note: Optional[str] = None

    ) -> bool:

        """Update obligation parameters."""

        conn = self._get_conn()

        cursor = conn.cursor()

        try:

            updates = []

            params = []

            if name is not None:

                updates.append("name = ?")

                params.append(name.strip())

            if amount_cents is not None:

                require_cents(amount_cents)

                updates.append("amount_cents = ?")

                params.append(amount_cents)

            if due_day is not None:

                if type(due_day) is not int or not (1 <= due_day <= 31): raise ValueError("День списания от 1 до 31.")

                updates.append("due_day = ?")

                params.append(due_day)

            if category_id is not None:

                updates.append("category_id = ?")

                params.append(category_id if category_id != "" else None)

            if payment_account_id is not None:

                updates.append("payment_account_id = ?")

                params.append(payment_account_id if payment_account_id != "" else None)

            if note is not None:

                updates.append("note = ?")

                params.append(note.strip() if note else None)

            if not updates:

                return True

            params.append(obligation_id)

            cursor.execute(f"UPDATE obligations SET {', '.join(updates)} WHERE id = ?;", tuple(params))

            if cursor.rowcount > 0:

                cursor.execute("SELECT id, name, amount_cents, due_day, category_id, payment_account_id, note, is_active FROM obligations WHERE id = ?;", (obligation_id,))

                o_row = cursor.fetchone()

                if o_row:

                    self._get_sync_engine().record_change_event("OBLIGATION", obligation_id, "UPDATE", dict(o_row), cursor=cursor)

            self._commit(conn)

            self._save_if_encrypted()

            return cursor.rowcount > 0

        finally:

            self._close_if_local(conn)

    @atomic_operation
    def archive_obligation(self, obligation_id: str) -> bool:

        """Soft-archive obligation."""

        conn = self._get_conn()

        cursor = conn.cursor()

        try:

            cursor.execute("UPDATE obligations SET is_active = 0 WHERE id = ?;", (obligation_id,))

            if cursor.rowcount > 0:

                self._get_sync_engine().record_change_event("OBLIGATION", obligation_id, "UPDATE", {"id": obligation_id, "is_active": 0}, cursor=cursor)

            self._commit(conn)

            self._save_if_encrypted()

            return cursor.rowcount > 0

        finally:

            self._close_if_local(conn)

    def get_obligations(self, month_year: Optional[str] = None) -> List[Dict[str, Any]]:
        month_year=self._obligation_month(month_year)
        conn=self._get_conn(); cursor=conn.cursor()
        try:
            cursor.execute("""SELECT o.*,c.name AS category_name,c.icon AS category_icon,
                a.name AS payment_account_name,a.currency AS payment_currency,
                op.id AS payment_id,op.paid_amount_cents,op.paid_at,op.transaction_id
                FROM obligations o LEFT JOIN categories c ON o.category_id=c.id
                LEFT JOIN accounts a ON o.payment_account_id=a.id
                LEFT JOIN obligation_payments op ON op.obligation_id=o.id AND op.month_year=?
                WHERE o.is_active=1 ORDER BY o.due_day,o.name""",(month_year,))
            rows=cursor.fetchall(); result=[]
            for row in rows:
                r=dict(row); paid=r.get("paid_amount_cents") or 0
                cursor.execute("SELECT value FROM system_meta WHERE key=?",(self._obligation_components_key(r["id"],month_year),))
                components=cursor.fetchone()
                if components:
                    paid=self._obligation_paid_total(cursor,json.loads(components["value"]),r.get('payment_currency') or 'RUB')
                elif r.get("transaction_id"):
                    paid=self._obligation_paid_total(cursor,{"transactions":{r["transaction_id"]:paid}},r.get('payment_currency') or 'RUB') if paid>0 else 0
                remaining=max(0,r["amount_cents"]-paid)
                result.append({"id":r["id"],"name":r["name"],"amount_cents":r["amount_cents"],
                    "amount_rub":cents_to_rubles(r["amount_cents"]),"due_day":r["due_day"],"note":r["note"],
                    "category_id":r["category_id"],"category_name":r.get("category_name") or "Без категории",
                    "category_icon":r.get("category_icon") or "tag","payment_account_id":r["payment_account_id"],
                    "payment_account_name":r.get("payment_account_name") or "Не назначен",
                    "currency":r.get("payment_currency") or "RUB",
                    "is_paid_this_month":remaining==0,"paid_amount_cents":paid,"paid_amount_rub":cents_to_rubles(paid),
                    "remaining_cents":remaining,"remaining_rub":cents_to_rubles(remaining),"paid_at":r.get("paid_at"),
                    "transaction_id":r.get("transaction_id"),"month_year":month_year})
            return result
        finally:
            self._close_if_local(conn)

    @atomic_operation
    def mark_obligation_paid(self, obligation_id: str, month_year: Optional[str] = None,
                             transaction_id: Optional[str] = None, paid_amount_cents: Optional[int] = None) -> bool:
        month_year=self._obligation_month(month_year)
        conn=self._get_conn();cursor=conn.cursor()
        cursor.execute("SELECT o.amount_cents,COALESCE(a.currency,'RUB') AS currency FROM obligations o LEFT JOIN accounts a ON a.id=o.payment_account_id WHERE o.id=? AND o.is_active=1",(obligation_id,))
        obligation=cursor.fetchone()
        if obligation is None: return False
        amount=obligation["amount_cents"] if paid_amount_cents is None else paid_amount_cents
        require_cents(amount)
        key=self._obligation_components_key(obligation_id,month_year)
        cursor.execute("SELECT * FROM obligation_payments WHERE obligation_id=? AND month_year=?",(obligation_id,month_year))
        existing=cursor.fetchone()
        cursor.execute("SELECT value FROM system_meta WHERE key=?",(key,)); component_row=cursor.fetchone()
        if component_row:
            components=json.loads(component_row["value"])
        else:
            components={"manual_cents":0,"transactions":{}}
            if existing:
                if existing["transaction_id"]:
                    components["transactions"][existing["transaction_id"]]=existing["paid_amount_cents"]
                else:
                    components["manual_cents"]=max(0,existing["paid_amount_cents"])
        if transaction_id:
            currencies = {r['currency'] for r in cursor.execute("SELECT DISTINCT a.currency FROM postings p JOIN accounts a ON a.id=p.account_id WHERE p.transaction_id=? AND a.account_type IN ('ASSET','LIABILITY')", (transaction_id,))}
            if currencies != {obligation['currency']}:
                raise ValueError('Валюта связанной операции не совпадает с валютой обязательства.')
            cursor.execute("SELECT COALESCE(SUM(p.amount_cents),0) AS amount FROM postings p JOIN transactions t ON t.id=p.transaction_id JOIN accounts a ON a.id=p.account_id WHERE t.id=? AND t.is_voided=0 AND p.posting_type='DEBIT' AND a.account_type IN ('EXPENSE','LIABILITY')",(transaction_id,))
            available=cursor.fetchone()["amount"]
            if available<=0 or amount>available:
                raise ValueError("Связанная операция не подтверждает указанную сумму оплаты.")
            previous=components["transactions"].get(transaction_id)
            if previous is not None and previous != amount:
                raise ValueError("Операция уже связана с другой суммой оплаты.")
            components["transactions"][transaction_id]=amount
        else:
            # A manual mark is a deliberate monthly status/snapshot, not a new money transfer.
            components={"manual_cents":amount,"transactions":{}}
        total=self._obligation_paid_total(cursor,components)
        pay_id=existing["id"] if existing else generate_uuid(); paid_at=current_iso_time()
        cursor.execute("INSERT INTO obligation_payments(id,obligation_id,month_year,transaction_id,paid_amount_cents,paid_at) VALUES(?,?,?,?,?,?) ON CONFLICT(obligation_id,month_year) DO UPDATE SET transaction_id=excluded.transaction_id,paid_amount_cents=excluded.paid_amount_cents,paid_at=excluded.paid_at",(pay_id,obligation_id,month_year,transaction_id,total,paid_at))
        cursor.execute("INSERT INTO system_meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",(key,json.dumps(components,ensure_ascii=False)))
        payload={"id":pay_id,"obligation_id":obligation_id,"month_year":month_year,"transaction_id":transaction_id,"paid_amount_cents":total,"paid_at":paid_at,"components":components}
        self._get_sync_engine().record_change_event("OBLIGATION_PAYMENT",pay_id,"INSERT",payload,cursor=cursor)
        return True

    @atomic_operation
    def set_initial_balance(self, account_id: str, balance_cents: int, date: Optional[str] = None) -> str:
        require_cents(balance_cents, allow_zero=True)
        conn=self._get_conn(); cursor=conn.cursor()
        cursor.execute("SELECT * FROM accounts WHERE id=?",(account_id,)); acc=cursor.fetchone()
        if acc is None or acc["account_type"] not in ("ASSET","LIABILITY"):
            raise ValueError("Начальный остаток поддерживается только для финансового счёта.")
        from datetime import date as calendar_date
        tx_date=date or current_iso_time()[:10]; calendar_date.fromisoformat(tx_date)
        cursor.execute("SELECT id FROM accounts WHERE code='3010'"); eq=cursor.fetchone()
        if eq is None: raise ValueError("Счёт капитала не найден.")
        key=f"init_bal_{account_id}"
        cursor.execute("SELECT id FROM transactions WHERE (idempotency_key=? OR idempotency_key LIKE ?) AND is_voided=0",(key,key+":%"))
        previous=cursor.fetchall()
        for old_opening in previous:
            self.void_transaction(old_opening["id"],"Замена начального остатка")
        cursor.execute("UPDATE accounts SET initial_balance_cents=? WHERE id=?",(balance_cents,account_id))
        cursor.execute("SELECT * FROM accounts WHERE id=?",(account_id,))
        self._get_sync_engine().record_change_event("ACCOUNT",account_id,"UPDATE",dict(cursor.fetchone()),cursor=cursor)
        if balance_cents:
            ident=generate_uuid()
            debit,credit=(eq["id"],account_id) if acc["account_type"]=="LIABILITY" else (account_id,eq["id"])
            transaction=Transaction(id=ident,tx_date=tx_date,tx_type="ADJUSTMENT",description=f"Начальный остаток счета '{acc['name']}'",postings=[
                Posting(generate_uuid(),ident,debit,balance_cents,"DEBIT",ownership_scope=acc["ownership_scope"]),
                Posting(generate_uuid(),ident,credit,balance_cents,"CREDIT",ownership_scope=acc["ownership_scope"])])
            cursor.execute("SELECT 1 FROM transactions WHERE idempotency_key=?",(key,))
            opening_key=key+":"+ident if cursor.fetchone() else key
            self.record_transaction(transaction,idempotency_key=opening_key)
        return account_id

    @atomic_operation
    def batch_onboarding_setup(

        self,

        balances: List[Dict[str, Any]],

        obligations: Optional[List[Dict[str, Any]]] = None,

        owner_member_id: Optional[str] = None

    ) -> Dict[str, Any]:

        """

        Convenience onboarding setup to initialize multiple accounts and monthly obligations in one go.

        - balances: [{'account_id': '...', 'balance_cents': 5000000, 'credit_limit_cents': 15000000}, ...]

        - obligations: [{'name': 'Аренда', 'amount_cents': 3500000, 'due_day': 20, 'category_id': '...'}, ...]

        """

        applied_balances = []

        for b in balances:

            acc_id = b.get("account_id")

            cents = require_cents(b.get("balance_cents", 0), allow_zero=True)

            self.set_initial_balance(acc_id, cents)

            if "credit_limit_cents" in b and b["credit_limit_cents"] is not None:

                self.update_account(acc_id, name=None, credit_limit_cents=require_cents(b["credit_limit_cents"], allow_zero=True))

            applied_balances.append({"account_id": acc_id, "balance_cents": cents})

        applied_obligations = []

        if obligations:

            for o in obligations:

                obl = self.create_obligation(

                    name=o.get("name", "Обязательство"),

                    amount_cents=require_cents(o.get("amount_cents", 0)),

                    due_day=o.get("due_day", 1),

                    category_id=o.get("category_id"),

                    payment_account_id=o.get("payment_account_id"),

                    note=o.get("note")

                )

                applied_obligations.append({"id": obl.id, "name": obl.name, "amount_cents": obl.amount_cents})

        overview = self.get_financial_overview()

        return {

            "status": "success",

            "applied_balances": applied_balances,

            "applied_obligations": applied_obligations,

            "overview": overview

        }

    @atomic_operation
    def unmark_obligation_paid(self, obligation_id: str, month_year: Optional[str] = None) -> bool:

        """Remove paid status of an obligation for the specified month."""

        month_year = self._obligation_month(month_year)
        if not month_year:

            from datetime import datetime

            month_year = datetime.now().strftime("%Y-%m")

        conn = self._get_conn()

        cursor = conn.cursor()

        try:

            cursor.execute("DELETE FROM obligation_payments WHERE obligation_id = ? AND month_year = ?;", (obligation_id, month_year))
            deleted = cursor.rowcount
            # Keep the reset tombstone so delayed allocations cannot resurrect a mark.

            if deleted > 0:

                self._get_sync_engine().record_change_event("OBLIGATION_PAYMENT", obligation_id, "DELETE", {"obligation_id": obligation_id, "month_year": month_year}, cursor=cursor)

            self._commit(conn)

            self._save_if_encrypted()

            return deleted > 0

        finally:

            self._close_if_local(conn)

    def calculate_unpaid_obligations_cents(self, month_year: Optional[str] = None) -> Tuple[int, int, int]:

        """

        Calculate (unpaid_cents, total_obligations_cents, paid_obligations_cents) for the given month.

        """

        obls = self.get_obligations(month_year)

        obls = [o for o in obls if o.get("currency", "RUB") == "RUB"]
        total_cents = sum(o["amount_cents"] for o in obls)

        paid_cents = sum(min(o["amount_cents"],o["paid_amount_cents"]) for o in obls)

        unpaid_cents = sum(o["remaining_cents"] for o in obls)

        return unpaid_cents, total_cents, paid_cents

    # ---------------------------------------------------------

    # Stage 7: Financial Analytics & Visual Spending Breakdown

    # ---------------------------------------------------------

    def get_spending_analytics(self, period="current_month", start_date=None, end_date=None):
        from family_finances_os.reporting import analytics
        return analytics(self, period, start_date, end_date)

    def get_cash_flow_forecast(self, days=30, include_burn_rate=True, custom_daily_burn_cents=None, safety_buffer_cents=0):
        from family_finances_os.reporting import forecast
        return forecast(self, days, include_burn_rate, custom_daily_burn_cents, safety_buffer_cents)

    def _reservation_account(self, cursor, account_id):
        """Tracking objects currently use RUB; linked money must be active assets."""
        if not account_id:
            return None
        cursor.execute("SELECT * FROM accounts WHERE id = ? AND is_active = 1", (account_id,))
        row = cursor.fetchone()
        if row is None or row["account_type"] != "ASSET":
            raise ValueError("Связанный счёт должен быть действующим счётом активов.")
        if row["currency"] != "RUB":
            raise ValueError("Цели и конверты в рублях нельзя связывать со счётом в другой валюте.")
        return row

    @staticmethod
    def _reservation_cents(value, allow_zero=False):
        from family_finances_os.models import require_cents
        return require_cents(value, allow_zero=allow_zero)

    @staticmethod
    def _reservation_date(value):
        from datetime import date
        if value:
            date.fromisoformat(value)
        return value or None

    def _reservation_reference(self, cursor, table, ident):
        if ident:
            if table not in ("categories", "members"):
                raise ValueError("Недопустимый справочник.")
            cursor.execute(f"SELECT id FROM {table} WHERE id = ?", (ident,))
            if cursor.fetchone() is None:
                raise ValueError("Связанная запись не найдена.")

    def _reservation_snapshot(self, cursor, table, ident, entity, change_type="UPDATE"):
        if table not in ("goals", "envelopes", "envelope_operations", "goal_contributions"):
            raise ValueError("Недопустимый объект накоплений.")
        cursor.execute(f"SELECT * FROM {table} WHERE id = ?", (ident,))
        row = cursor.fetchone()
        self._get_sync_engine().record_change_event(entity, ident, change_type, dict(row), cursor=cursor)

    def _reservation_request(self, cursor, operation, key, payload):
        if not key:
            return None, None, None
        token = hashlib.sha256(str(key).encode("utf-8")).hexdigest()
        meta_key = "reservation-command-v1:" + token
        digest = hashlib.sha256(json.dumps([operation, payload],sort_keys=True,
                    ensure_ascii=False,separators=(",",":")).encode("utf-8")).hexdigest()
        cursor.execute("SELECT value FROM system_meta WHERE key = ?",(meta_key,))
        row = cursor.fetchone()
        if row:
            saved = json.loads(row["value"])
            if saved["hash"] != digest:
                raise ValueError("Ключ идемпотентности уже использован с другими параметрами.")
            return meta_key, digest, saved["result"]
        # The operation ID also travels in CDC. A retry received by another
        # device must not depend on a cache that only exists on the first peer.
        cursor.execute("SELECT * FROM envelope_operations WHERE id = ?",
                       ("envelope-operation-v1:" + token,))
        prior = cursor.fetchone()
        if prior:
            types = {"envelope-deposit":"DEPOSIT","envelope-withdraw":"WITHDRAW",
                     "envelope-transfer":"TRANSFER"}
            if operation not in types or prior["operation_type"] != types[operation]:
                raise ValueError("Ключ идемпотентности уже использован другой операцией.")
            relation = {"envelope-deposit":"source_account_id",
                        "envelope-withdraw":"destination_account_id",
                        "envelope-transfer":"target_envelope_id"}[operation]
            expected = ([prior["envelope_id"],prior["amount_cents"],prior[relation],
                         prior["note"],prior["member_id"]]
                        if operation != "envelope-transfer" else
                        [prior["envelope_id"],prior[relation],prior["amount_cents"],
                         prior["note"],prior["member_id"]])
            if payload != expected:
                raise ValueError("Ключ идемпотентности уже использован с другими параметрами.")
            cursor.execute("SELECT current_amount_cents FROM envelopes WHERE id = ?",
                           (prior["envelope_id"],))
            balance = cursor.fetchone()["current_amount_cents"]
            if operation == "envelope-transfer":
                cursor.execute("SELECT current_amount_cents FROM envelopes WHERE id = ?",
                               (prior["target_envelope_id"],))
                destination_balance = cursor.fetchone()["current_amount_cents"]
                result = {"status":"success","from_envelope_id":prior["envelope_id"],
                          "to_envelope_id":prior["target_envelope_id"],
                          "amount_rub":cents_to_rubles(prior["amount_cents"]),
                          "from_new_balance_rub":cents_to_rubles(balance),
                          "to_new_balance_rub":cents_to_rubles(destination_balance)}
            else:
                cursor.execute("SELECT id FROM transactions WHERE idempotency_key = ?",
                               ("envelope-bank-v1:" + token,))
                bank_tx = cursor.fetchone()
                result = {"status":"success","envelope_id":prior["envelope_id"],
                          "amount_rub":cents_to_rubles(prior["amount_cents"]),
                          "new_balance_rub":cents_to_rubles(balance),
                          "transaction_id":bank_tx["id"] if bank_tx else None}
            return meta_key, digest, result
        return meta_key, digest, None

    def _reservation_result(self, cursor, request, result):
        key, digest, _ = request
        if key:
            cursor.execute("INSERT INTO system_meta (key,value) VALUES (?,?)",
                (key,json.dumps({"hash":digest,"result":result},ensure_ascii=False)))
        return result

    def _envelope_operation(self, cursor, envelope_id, operation_type, amount_cents,
                            source_account_id=None, destination_account_id=None,
                            target_envelope_id=None, note=None, member_id=None,
                            operation_id=None, emit=True):
        op_id = operation_id or generate_uuid()
        cursor.execute("""INSERT INTO envelope_operations
            (id,envelope_id,operation_type,amount_cents,source_account_id,
             destination_account_id,target_envelope_id,note,member_id,created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (op_id,envelope_id,operation_type,amount_cents,source_account_id,
             destination_account_id,target_envelope_id,note,member_id,current_iso_time()))
        if emit:
            self._reservation_snapshot(cursor,"envelope_operations",op_id,"ENVELOPE_OPERATION","INSERT")
        return op_id

    @atomic_operation
    def create_goal(

        self,

        name: str,

        target_amount_cents: int,

        target_date: Optional[str] = None,

        account_id: Optional[str] = None,

        category_id: Optional[str] = None,

        icon: str = "🎯",

        note: Optional[str] = None,

        initial_saved_cents: int = 0

    ) -> Goal:

        if not name or not name.strip():

            raise ValueError("Название цели не может быть пустым.")

        self._reservation_cents(target_amount_cents)
        self._reservation_cents(initial_saved_cents, allow_zero=True)
        target_date = self._reservation_date(target_date)

        if target_amount_cents <= 0:

            raise ValueError("Целевая сумма должна быть строго больше нуля.")

        if initial_saved_cents < 0:

            raise ValueError("Начальные накопления не могут быть отрицательными.")

        goal_id = generate_uuid()

        conn = self._get_conn()

        cursor = conn.cursor()


        # Validate references before writing; never silently relink financial state.
        account_id = str(account_id).strip() if account_id else None
        self._reservation_account(cursor, account_id)
        category_id = str(category_id).strip() if category_id else None
        self._reservation_reference(cursor, "categories", category_id)
        try:

            cursor.execute("""

            INSERT INTO goals

            (id, name, target_amount_cents, current_amount_cents, target_date, account_id, category_id, icon, note, is_completed, is_active, created_at)

            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?);

            """, (

                goal_id,

                name.strip(),

                target_amount_cents,

                initial_saved_cents,

                target_date,

                account_id,

                category_id,

                icon or "🎯",

                note.strip() if note else None,

                1 if initial_saved_cents >= target_amount_cents else 0,

                current_iso_time()

            ))

            payload = {

                "id": goal_id,

                "name": name.strip(),

                "target_amount_cents": target_amount_cents,

                "current_amount_cents": initial_saved_cents,

                "target_date": target_date,

                "account_id": account_id,

                "category_id": category_id,

                "icon": icon or "🎯",

                "note": note.strip() if note else None,

                "is_completed": 1 if initial_saved_cents >= target_amount_cents else 0,

                "is_active": 1,

                "created_at": current_iso_time()

            }

            self._get_sync_engine().record_change_event("GOAL", goal_id, "INSERT", payload, cursor=cursor)

            self._commit(conn)

            self._save_if_encrypted()

            return Goal(

                id=goal_id,

                name=name.strip(),

                target_amount_cents=target_amount_cents,

                current_amount_cents=initial_saved_cents,

                target_date=target_date,

                account_id=account_id,

                category_id=category_id,

                icon=icon or "🎯",

                note=note.strip() if note else None,

                is_completed=initial_saved_cents >= target_amount_cents,

                is_active=True

            )

        finally:

            self._close_if_local(conn)

    @atomic_operation
    def update_goal(

        self,

        goal_id: str,

        name: Optional[str] = None,

        target_amount_cents: Optional[int] = None,

        target_date: Optional[str] = None,

        account_id: Optional[str] = None,

        category_id: Optional[str] = None,

        icon: Optional[str] = None,

        note: Optional[str] = None

    ) -> bool:

        conn = self._get_conn()

        cursor = conn.cursor()

        try:

            updates = []

            params = []

            if name is not None:

                if not name.strip():
                    raise ValueError("Название цели не может быть пустым.")

                updates.append("name = ?")

                params.append(name.strip())

            if target_amount_cents is not None:

                self._reservation_cents(target_amount_cents)

                if target_amount_cents <= 0:

                    raise ValueError("Целевая сумма должна быть строго больше нуля.")

                updates.append("target_amount_cents = ?")

                params.append(target_amount_cents)

            if target_date is not None:

                updates.append("target_date = ?")

                params.append(self._reservation_date(target_date))

            if account_id is not None:

                self._reservation_account(cursor, account_id or None)

                updates.append("account_id = ?")

                params.append(account_id or None)

            if category_id is not None:

                self._reservation_reference(cursor, "categories", category_id or None)

                updates.append("category_id = ?")

                params.append(category_id or None)

            if icon is not None:

                updates.append("icon = ?")

                params.append(icon)

            if note is not None:

                updates.append("note = ?")

                params.append(note.strip() if note else None)

            if not updates:

                return True

            params.append(goal_id)

            cursor.execute(f"UPDATE goals SET {', '.join(updates)} WHERE id = ?;", tuple(params))

            if cursor.rowcount > 0:

                cursor.execute("SELECT * FROM goals WHERE id = ?;", (goal_id,))

                row = cursor.fetchone()

                if row:

                    is_comp = 1 if row["current_amount_cents"] >= row["target_amount_cents"] else 0

                    cursor.execute("UPDATE goals SET is_completed = ? WHERE id = ?;", (is_comp, goal_id))

                    self._reservation_snapshot(cursor, "goals", goal_id, "GOAL")

                self._commit(conn)

                self._save_if_encrypted()

                return True

            return False

        finally:

            self._close_if_local(conn)

    @atomic_operation
    def archive_goal(self, goal_id: str) -> bool:

        conn = self._get_conn()

        cursor = conn.cursor()

        try:

            cursor.execute("UPDATE goals SET is_active = 0 WHERE id = ?;", (goal_id,))

            if cursor.rowcount > 0:

                self._reservation_snapshot(cursor, "goals", goal_id, "GOAL")

                self._commit(conn)

                self._save_if_encrypted()

                return True

            return False

        finally:

            self._close_if_local(conn)

    def get_goals(self, include_completed: bool = True) -> List[Dict[str, Any]]:

        conn = self._get_conn()

        cursor = conn.cursor()

        try:

            query = """

            SELECT g.*, a.name as account_name, a.code as account_code, c.name as category_name

            FROM goals g

            LEFT JOIN accounts a ON g.account_id = a.id

            LEFT JOIN categories c ON g.category_id = c.id

            WHERE g.is_active = 1

            """

            if not include_completed:

                query += " AND g.is_completed = 0"

            query += " ORDER BY g.is_completed ASC, g.created_at DESC;"

            cursor.execute(query)

            rows = cursor.fetchall()

            from datetime import date

            today = date.today()

            res = []

            for r in rows:

                target_cents = r["target_amount_cents"]

                current_cents = r["current_amount_cents"]

                rem_cents = max(0, target_cents - current_cents)

                pct = round((current_cents / target_cents) * 100, 1) if target_cents > 0 else 0.0

                if pct > 100.0:

                    pct = 100.0

                rec_monthly_rub = None

                target_date_str = r["target_date"]

                if target_date_str and rem_cents > 0:

                    try:

                        t_parts = target_date_str[:10].split("-")

                        t_date = date(int(t_parts[0]), int(t_parts[1]), int(t_parts[2]))

                        days_left = (t_date - today).days

                        if days_left > 0:

                            # Estimated 30-day instalments, including a payment now.
                            # Ceil the cents so the suggested instalments cannot
                            # undershoot the remaining amount by a fractional cent.
                            months_left = max(1, (days_left + 29) // 30)

                            monthly_cents = (rem_cents + months_left - 1) // months_left

                            rec_monthly_rub = cents_to_rubles(monthly_cents)

                    except Exception:

                        pass

                res.append({

                    "id": r["id"],

                    "name": r["name"],

                    "target_amount_cents": target_cents,

                    "target_amount_rub": cents_to_rubles(target_cents),

                    "current_amount_cents": current_cents,

                    "current_amount_rub": cents_to_rubles(current_cents),

                    "remaining_cents": rem_cents,

                    "remaining_rub": cents_to_rubles(rem_cents),

                    "progress_percent": pct,

                    "target_date": target_date_str,

                    "recommended_monthly_rub": rec_monthly_rub,

                    "recommendation_is_estimate": True,

                    "tracking_mode": "INFORMATIONAL",

                    "currency": "RUB",

                    "account_id": r["account_id"],

                    "account_name": r["account_name"],

                    "category_id": r["category_id"],

                    "category_name": r["category_name"],

                    "icon": r["icon"] or "🎯",

                    "note": r["note"],

                    "is_completed": bool(r["is_completed"]),

                    "is_active": bool(r["is_active"]),

                    "created_at": r["created_at"]

                })

            return res

        finally:

            self._close_if_local(conn)

    @atomic_operation
    def contribute_to_goal(
        self, goal_id: str, amount_cents: int,
        source_account_id: Optional[str] = None, note: Optional[str] = None,
        member_id: Optional[str] = None, idempotency_key: Optional[str] = None
    ) -> Dict[str, Any]:
        """Track a contribution and its optional bank transfer as one atomic command."""
        self._reservation_cents(amount_cents)
        conn = self._get_conn()
        cursor = conn.cursor()
        try:
            request = {"goal_id":goal_id,"amount_cents":amount_cents,
                       "source_account_id":source_account_id or None,
                       "note":note or None,"member_id":member_id or None}
            request_json = json.dumps(request,sort_keys=True,ensure_ascii=False,separators=(",",":"))
            request_hash = hashlib.sha256(request_json.encode("utf-8")).hexdigest()
            meta_key = None
            contrib_id = generate_uuid()
            if idempotency_key:
                token = hashlib.sha256(str(idempotency_key).encode("utf-8")).hexdigest()
                meta_key = "goal-request-v1:" + token
                contrib_id = "goal-contribution-v1:" + token
                cursor.execute("SELECT value FROM system_meta WHERE key = ?",(meta_key,))
                cached = cursor.fetchone()
                if cached:
                    saved = json.loads(cached["value"])
                    if saved["request_hash"] != request_hash:
                        raise ValueError("Ключ идемпотентности уже использован с другими параметрами взноса.")
                    return saved["result"]
                cursor.execute("SELECT * FROM goal_contributions WHERE id = ?",(contrib_id,))
                existing = cursor.fetchone()
                if existing:
                    if (existing["goal_id"] != goal_id or existing["amount_cents"] != amount_cents
                            or existing["source_account_id"] != (source_account_id or None)
                            or (existing["note"] or None) != (note or None)):
                        raise ValueError("Ключ идемпотентности уже использован с другими параметрами взноса.")
                    cursor.execute("SELECT * FROM goals WHERE id = ?",(goal_id,))
                    current = cursor.fetchone()
                    return {"status":"success","goal_id":goal_id,
                            "new_current_cents":current["current_amount_cents"],
                            "new_current_rub":cents_to_rubles(current["current_amount_cents"]),
                            "is_completed":bool(current["is_completed"]),
                            "transaction_id":existing["transaction_id"]}
            cursor.execute("SELECT * FROM goals WHERE id = ? AND is_active = 1",(goal_id,))
            goal = cursor.fetchone()
            if goal is None:
                raise ValueError("Цель не найдена или неактивна.")
            self._reservation_reference(cursor,"members",member_id)
            self._reservation_account(cursor,goal["account_id"])
            tx_id = None
            if source_account_id:
                self._reservation_account(cursor,source_account_id)
                destination = goal["account_id"]
                if not destination:
                    cursor.execute("SELECT id FROM accounts WHERE code = '1030' AND is_active = 1")
                    reserve = cursor.fetchone()
                    destination = reserve["id"] if reserve else None
                if not destination:
                    raise ValueError("Выберите счёт назначения для денежного взноса.")
                self._reservation_account(cursor,destination)
                if destination != source_account_id:
                    if self.get_account_balance_cents(source_account_id) < amount_cents:
                        raise ValueError("Недостаточно средств на исходном счёте.")
                    tx_id = self.record_transfer(
                        from_account_id=source_account_id,to_account_id=destination,
                        amount_cents=amount_cents,description=f"Пополнение цели: {goal['name']}",
                        created_by_member_id=member_id,
                        idempotency_key=("goal-transfer-v1:"+token) if meta_key else None)
            new_current = goal["current_amount_cents"] + amount_cents
            self._reservation_cents(new_current, allow_zero=True)
            complete = new_current >= goal["target_amount_cents"]
            cursor.execute("UPDATE goals SET current_amount_cents = ?, is_completed = ? WHERE id = ?",
                           (new_current,int(complete),goal_id))
            cursor.execute("""INSERT INTO goal_contributions
                (id,goal_id,amount_cents,transaction_id,source_account_id,note,created_at)
                VALUES (?,?,?,?,?,?,?)""",
                (contrib_id,goal_id,amount_cents,tx_id,source_account_id or None,note or None,current_iso_time()))
            self._reservation_snapshot(cursor,"goals",goal_id,"GOAL")
            self._reservation_snapshot(cursor,"goal_contributions",contrib_id,"GOAL_CONTRIBUTION","INSERT")
            result = {"status":"success","goal_id":goal_id,"new_current_cents":new_current,
                      "new_current_rub":cents_to_rubles(new_current),
                      "is_completed":bool(complete),"transaction_id":tx_id}
            if meta_key:
                cursor.execute("INSERT INTO system_meta (key,value) VALUES (?,?)",
                    (meta_key,json.dumps({"request_hash":request_hash,"result":result},ensure_ascii=False)))
            self._commit(conn)
            self._save_if_encrypted()
            return result
        finally:
            self._close_if_local(conn)


    # ---------------------------------------------------------

    # 9. Debts & Debt Repayments (Stage 9 Liabilities)

    # ---------------------------------------------------------


    @staticmethod
    def calculate_credit_payoff_scenarios(
        debt_cents: int,
        interest_rate_percent: float = 24.8,
        min_payment_percent: float = 3.0,
        grace_period_days: int = 120,
        grace_due_date: Optional[str] = None,
        as_of_date: Optional[str] = None,
        custom_payment_cents: Optional[int] = None,
        custom_payment_percent: Optional[float] = None
    ) -> Dict[str, Any]:
        """Return deterministic, explicitly labelled credit estimate scenarios."""
        from family_finances_os.debt_math import payoff_scenarios
        return payoff_scenarios(debt_cents, interest_rate_percent, min_payment_percent,
                                grace_period_days, grace_due_date, as_of_date,
                                custom_payment_cents, custom_payment_percent)

    @staticmethod
    def calculate_credit_card_banking_metrics(
        debt_cents: int,
        credit_limit_cents: int = 0,
        interest_rate_percent: float = 24.8,
        grace_period_days: int = 120,
        grace_due_date: str = None,
        min_payment_percent: float = 3.0,
        late_penalty_rate_percent: float = 36.0,
        as_of_date: str = None
    ) -> dict:
        """Estimate indicators; no calculated interest is posted to the ledger."""
        from family_finances_os.debt_math import banking_metrics
        return banking_metrics(debt_cents, credit_limit_cents, interest_rate_percent,
                               grace_period_days, grace_due_date, min_payment_percent,
                               late_penalty_rate_percent, as_of_date)

    @atomic_operation
    def create_debt(
        self,
        name: str,
        subtype: str = "CONSUMER_LOAN",
        ownership_scope: str = "COMMON",
        credit_limit_cents: int = 0,
        initial_debt_cents: int = 0,
        monthly_payment_cents: int = 0,
        due_day: Optional[int] = None,
        receive_money: bool = False,
        destination_account_id: Optional[str] = None,
        description: Optional[str] = None,
        owner_member_id: Optional[str] = None,
        tx_date: Optional[str] = None,
        interest_rate_percent: float = 24.8,
        grace_period_days: int = 120,
        grace_due_date: Optional[str] = None,
        min_payment_percent: float = 3.0,
        late_penalty_rate_percent: float = 36.0
    ) -> Dict[str, Any]:
        if not name or not name.strip():
            raise ValueError("Название задолженности не может быть пустым.")

        valid_subtypes = {
            "CREDIT_CARD", "MORTGAGE", "CONSUMER_LOAN", "AUTO_LOAN",
            "PERSONAL_DEBT", "INSTALLMENT_BNPL", "LOAN"
        }
        if subtype not in valid_subtypes:
            raise ValueError(f"Недопустимый тип задолженности: {subtype}")

        from family_finances_os.debt_math import integer_amount, validate_terms
        credit_limit_cents = integer_amount(credit_limit_cents, "Кредитный лимит")
        initial_debt_cents = integer_amount(initial_debt_cents, "Начальный долг")
        monthly_payment_cents = integer_amount(monthly_payment_cents, "Ежемесячный платёж")
        terms = validate_terms(interest_rate_percent, grace_period_days, grace_due_date,
                               min_payment_percent, late_penalty_rate_percent)
        if due_day is not None and (isinstance(due_day, bool) or not isinstance(due_day, int) or not 1 <= due_day <= 31):
            raise ValueError("День платежа должен быть от 1 до 31.")
        if monthly_payment_cents and due_day is None:
            raise ValueError("Укажите день ежемесячного платежа.")
        if receive_money and not destination_account_id:
            raise ValueError("Укажите счёт зачисления заёмных средств.")
        if tx_date:
            from datetime import date
            date.fromisoformat(tx_date)

        conn = self._get_conn()
        cursor = conn.cursor()
        try:
            cursor.execute("""
            SELECT code FROM accounts 
            WHERE account_type = 'LIABILITY' AND code GLOB '2[0-9][0-9][0-9]'
            ORDER BY code DESC LIMIT 1;
            """)
            row = cursor.fetchone()
            if row and row["code"].isdigit():
                next_code = str(int(row["code"]) + 10)
            else:
                next_code = "2030"

            account_id = f"acc_liab_{generate_uuid()[:8]}"
            date_str = tx_date or current_iso_time()[:10]


            # Sanitize owner_member_id to prevent FOREIGN KEY constraint failed
            if owner_member_id:
                owner_member_id = str(owner_member_id).strip()
                cursor.execute("SELECT id FROM members WHERE id = ?;", (owner_member_id,))
                if not cursor.fetchone():
                    owner_member_id = None
            else:
                owner_member_id = None

            if destination_account_id:
                destination_account_id = str(destination_account_id).strip()
                cursor.execute("SELECT id FROM accounts WHERE id = ?;", (destination_account_id,))
                if not cursor.fetchone():
                    raise ValueError("Счёт зачисления не найден.")
            else:
                destination_account_id = None
            if subtype == "CREDIT_CARD":
                meta = {
                    "note": description.strip() if description else "",
                    **terms
                }
                desc_val = json.dumps(meta, ensure_ascii=False)
            else:
                desc_val = description.strip() if description else None

            cursor.execute("""
            INSERT INTO accounts (
                id, code, name, account_type, subtype, currency,
                ownership_scope, owner_member_id, description,
                credit_limit_cents, initial_balance_cents, is_active
            ) VALUES (?, ?, ?, 'LIABILITY', ?, 'RUB', ?, ?, ?, ?, ?, 1);
            """, (
                account_id,
                next_code,
                name.strip(),
                subtype,
                ownership_scope,
                owner_member_id,
                desc_val,
                credit_limit_cents,
                initial_debt_cents
            ))

            cursor.execute("SELECT * FROM accounts WHERE id = ?;", (account_id,))
            acc_row = cursor.fetchone()
            self._get_sync_engine().record_change_event("ACCOUNT", account_id, "INSERT", dict(acc_row), cursor=cursor)

            tx_id = None
            if initial_debt_cents > 0:
                tx_id = generate_uuid()
                if receive_money and destination_account_id:
                    dest_acc = self.get_account_by_id(destination_account_id)
                    if not dest_acc:
                        raise ValueError(f"Счет зачисления {destination_account_id} не найден.")
                    if dest_acc.account_type != "ASSET" or not dest_acc.is_active or dest_acc.currency != "RUB":
                        raise ValueError("Заём в рублях можно зачислить только на активный рублёвый счёт активов.")
                    tx_desc = f"Получение кредита / займа '{name.strip()}'"
                    postings = [
                        Posting(
                            id=generate_uuid(),
                            transaction_id=tx_id,
                            account_id=destination_account_id,
                            amount_cents=initial_debt_cents,
                            posting_type="DEBIT",
                            ownership_scope=ownership_scope,
                            purpose_allocation="SAFE_TO_SPEND",
                            note="Зачисление заёмных средств на счет"
                        ),
                        Posting(
                            id=generate_uuid(),
                            transaction_id=tx_id,
                            account_id=account_id,
                            amount_cents=initial_debt_cents,
                            posting_type="CREDIT",
                            ownership_scope=ownership_scope,
                            purpose_allocation="SAFE_TO_SPEND",
                            note="Образование обязательства (долга)"
                        )
                    ]
                else:
                    cursor.execute("SELECT id FROM accounts WHERE code = '3010';")
                    eq_row = cursor.fetchone()
                    if not eq_row:
                        cursor.execute("""
                        INSERT OR IGNORE INTO accounts (id, code, name, account_type, subtype, currency, ownership_scope, is_active)
                        VALUES ('acc_core_3010', '3010', 'Общий семейный капитал', 'EQUITY', 'COMMON_EQUITY', 'RUB', 'COMMON', 1);
                        """)
                        equity_id = "acc_core_3010"
                    else:
                        equity_id = eq_row["id"]
                    tx_desc = f"Фиксация начального остатка долга '{name.strip()}'"
                    postings = [
                        Posting(
                            id=generate_uuid(),
                            transaction_id=tx_id,
                            account_id=equity_id,
                            amount_cents=initial_debt_cents,
                            posting_type="DEBIT",
                            ownership_scope=ownership_scope,
                            purpose_allocation="SAFE_TO_SPEND",
                            note="Уменьшение начального капитала на сумму долга"
                        ),
                        Posting(
                            id=generate_uuid(),
                            transaction_id=tx_id,
                            account_id=account_id,
                            amount_cents=initial_debt_cents,
                            posting_type="CREDIT",
                            ownership_scope=ownership_scope,
                            purpose_allocation="SAFE_TO_SPEND",
                            note="Начальный остаток задолженности"
                        )
                    ]

                cursor.execute("""
                INSERT INTO transactions (id, tx_date, tx_type, description, is_voided, created_by_member_id)
                VALUES (?, ?, 'ADJUSTMENT', ?, 0, ?);
                """, (tx_id, date_str, tx_desc, owner_member_id))

                for p in postings:
                    cursor.execute("""
                    INSERT INTO postings (id, transaction_id, account_id, amount_cents, posting_type, ownership_scope, purpose_allocation, note)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                    """, (p.id, p.transaction_id, p.account_id, p.amount_cents, p.posting_type, p.ownership_scope, p.purpose_allocation, p.note))

                cursor.execute("SELECT * FROM transactions WHERE id = ?;", (tx_id,))
                transaction_payload = dict(cursor.fetchone())
                cursor.execute("SELECT p.*, a.code AS account_code FROM postings p JOIN accounts a ON a.id = p.account_id WHERE p.transaction_id = ? ORDER BY p.id;", (tx_id,))
                transaction_payload["postings"] = [dict(p) for p in cursor.fetchall()]
                self._get_sync_engine().record_change_event("TRANSACTION", tx_id, "INSERT", transaction_payload, cursor=cursor)

            obligation_id = None
            if monthly_payment_cents > 0 and due_day:
                obligation_id = generate_uuid()
                day_val = due_day
                ob_cat_id = DEBT_CATEGORY_MAP.get(subtype, "cat_debts")
                cursor.execute("SELECT id FROM categories WHERE id = ?;", (ob_cat_id,))
                if not cursor.fetchone():
                    cursor.execute("SELECT id FROM categories WHERE id = 'cat_debts';")
                    if not cursor.fetchone():
                        cursor.execute("""
                        INSERT OR IGNORE INTO categories (id, name, category_type, parent_id, icon, sort_order, is_active)
                        VALUES ('cat_debts', 'Кредиты, долги и займы', 'EXPENSE', NULL, '💳', 80, 1);
                        """)
                    cursor.execute("""
                    INSERT OR IGNORE INTO categories (id, name, category_type, parent_id, icon, sort_order, is_active)
                    VALUES (?, 'Погашение задолженности', 'EXPENSE', 'cat_debts', '💳', 81, 1);
                    """, (ob_cat_id,))
                cursor.execute("""
                INSERT INTO obligations (
                    id, name, amount_cents, due_day, category_id, payment_account_id,
                    note, is_active
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 1);
                """, (
                    obligation_id,
                    f"Платеж: {name.strip()}",
                    monthly_payment_cents,
                    day_val,
                    ob_cat_id,
                    account_id,
                    f"Автоматический ежемесячный платеж по долгу '{name.strip()}'"
                ))
                cursor.execute("SELECT * FROM obligations WHERE id = ?;", (obligation_id,))
                self._get_sync_engine().record_change_event("OBLIGATION", obligation_id, "INSERT", dict(cursor.fetchone()), cursor=cursor)

            self._commit(conn)
            self._save_if_encrypted()

            return {
                "status": "success",
                "account_id": account_id,
                "code": next_code,
                "name": name.strip(),
                "subtype": subtype,
                "initial_debt_rub": cents_to_rubles(initial_debt_cents),
                "credit_limit_rub": cents_to_rubles(credit_limit_cents),
                "transaction_id": tx_id,
                "obligation_id": obligation_id
            }
        finally:
            self._close_if_local(conn)

    @atomic_operation
    def update_credit_card_settings(
        self,
        account_id: str,
        interest_rate_percent: float = 24.8,
        grace_period_days: int = 120,
        grace_due_date: Optional[str] = None,
        min_payment_percent: float = 3.0,
        late_penalty_rate_percent: float = 36.0,
        credit_limit_cents: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Update banking terms and grace period due date for a credit card account.
        """
        from family_finances_os.debt_math import integer_amount, validate_terms
        terms = validate_terms(interest_rate_percent, grace_period_days, grace_due_date,
                               min_payment_percent, late_penalty_rate_percent)
        if credit_limit_cents is not None:
            credit_limit_cents = integer_amount(credit_limit_cents, "Кредитный лимит")
        conn = self._get_conn()
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT * FROM accounts WHERE id = ?;", (account_id,))
            row = cursor.fetchone()
            if not row:
                raise ValueError(f"Счет задолженности {account_id} не найден.")
            if row["account_type"] != "LIABILITY" or row["subtype"] != "CREDIT_CARD" or not row["is_active"]:
                raise ValueError("Настройки применимы только к активной кредитной карте.")

            current_desc = row["description"] or ""
            note = ""
            if current_desc.strip().startswith("{"):
                try:
                    parsed = json.loads(current_desc)
                    note = parsed.get("note", "")
                except Exception:
                    note = current_desc
            else:
                note = current_desc

            meta = {
                "note": note,
                **terms
            }
            new_desc = json.dumps(meta, ensure_ascii=False)

            if credit_limit_cents is not None:
                cursor.execute("""
                UPDATE accounts
                SET description = ?, credit_limit_cents = ?
                WHERE id = ?;
                """, (new_desc, credit_limit_cents, account_id))
            else:
                cursor.execute("""
                UPDATE accounts
                SET description = ?
                WHERE id = ?;
                """, (new_desc, account_id))

            cursor.execute("SELECT * FROM accounts WHERE id = ?;", (account_id,))
            updated_row = dict(cursor.fetchone())
            self._get_sync_engine().record_change_event("ACCOUNT", account_id, "UPDATE", updated_row, cursor=cursor)

            self._commit(conn)
            self._save_if_encrypted()

            return {
                "status": "success",
                "account_id": account_id,
                "updated": True,
                "metadata": meta
            }
        finally:
            self._close_if_local(conn)

    def get_debts_summary(self) -> Dict[str, Any]:
        """
        Get structured overview of all liabilities, debts, credit cards and loans,
        including banking grace period calculations and overdue penalty alerts.
        """
        conn = self._get_conn()
        cursor = conn.cursor()
        try:
            cursor.execute("""
            SELECT 
                a.id, a.code, a.name, a.subtype, a.currency, a.credit_limit_cents, a.ownership_scope,
                a.description,
                COALESCE(SUM(CASE WHEN p.posting_type = 'CREDIT' THEN p.amount_cents ELSE 0 END), 0) -
                COALESCE(SUM(CASE WHEN p.posting_type = 'DEBIT' THEN p.amount_cents ELSE 0 END), 0) as balance_cents
            FROM accounts a
            LEFT JOIN postings p ON a.id = p.account_id
                AND EXISTS (SELECT 1 FROM transactions t WHERE t.id = p.transaction_id AND t.is_voided = 0)
            WHERE a.account_type = 'LIABILITY' AND a.is_active = 1
            GROUP BY a.id
            ORDER BY a.code;
            """)
            rows = cursor.fetchall()

            ob_rows = self.get_obligations(current_iso_time()[:7])
            ob_by_acc = {}
            for ob in ob_rows:
                acc_id = ob["payment_account_id"]
                if acc_id:
                    ob_by_acc[acc_id] = {
                        "obligation_id": ob["id"],
                        "name": ob["name"],
                        "amount_cents": ob["amount_cents"],
                        "amount_rub": cents_to_rubles(ob["amount_cents"]),
                        "due_day": ob["due_day"],
                        "is_paid": ob["is_paid_this_month"],
                        "paid_amount_cents": ob["paid_amount_cents"],
                        "remaining_cents": ob["remaining_cents"]
                    }

            debts = []
            total_debt_cents = 0
            credit_cards_debt_cents = 0
            loans_debt_cents = 0
            urgent_cards_count = 0
            total_min_payments_cents = 0
            totals_by_currency = {}

            for r in rows:
                bal = max(0, r["balance_cents"])
                limit = r["credit_limit_cents"] or 0
                subtype = r["subtype"]
                currency = r["currency"]
                bucket = totals_by_currency.setdefault(currency, {"currency": currency, "total_debt_cents": 0,
                    "credit_cards_debt_cents": 0, "loans_debt_cents": 0, "total_min_payments_cents": 0})
                bucket["total_debt_cents"] += bal

                banking = None
                if subtype == "CREDIT_CARD":
                    bucket["credit_cards_debt_cents"] += bal
                    if currency == "RUB":
                        credit_cards_debt_cents += bal
                    avail_cents = max(0, limit - bal)

                    apr = 24.8
                    grace_days = 120
                    grace_due = None
                    min_pct = 3.0
                    late_penalty = 36.0
                    note = ""

                    raw_desc = r["description"] or ""
                    if raw_desc.strip().startswith("{"):
                        try:
                            parsed = json.loads(raw_desc)
                            apr = float(parsed.get("interest_rate_percent", 24.8))
                            grace_days = int(parsed.get("grace_period_days", 120))
                            grace_due = parsed.get("grace_due_date")
                            min_pct = float(parsed.get("min_payment_percent", 3.0))
                            late_penalty = float(parsed.get("late_penalty_rate_percent", 36.0))
                            note = parsed.get("note", "")
                        except Exception:
                            note = raw_desc
                    else:
                        note = raw_desc

                    try:
                        banking = self.calculate_credit_card_banking_metrics(
                            debt_cents=bal, credit_limit_cents=limit, interest_rate_percent=apr,
                            grace_period_days=grace_days, grace_due_date=grace_due,
                            min_payment_percent=min_pct, late_penalty_rate_percent=late_penalty)
                    except ValueError as exc:
                        # Legacy malformed terms must not hide the principal or
                        # silently produce guaranteed-looking rate estimates.
                        banking = {"status": "INVALID_TERMS", "status_label": "Проверьте условия карты",
                                   "status_color": "gray", "is_urgent": False, "is_overdue": False,
                                   "min_payment_cents": 0, "min_payment_rub": None,
                                   "min_payment_formatted": None, "warning_message": str(exc),
                                   "payoff_scenarios": None, "is_estimate": True}
                    if currency != "RUB":
                        banking = {"status": "UNSUPPORTED_CURRENCY", "status_label": "Укажите валютные условия",
                                   "status_color": "gray", "is_urgent": False, "is_overdue": False,
                                   "min_payment_cents": 0, "min_payment_rub": None,
                                   "min_payment_formatted": None, "payoff_scenarios": None,
                                   "is_estimate": True,
                                   "warning_message": "Расчётная модель с минимумом 150 ₽ не применяется к другой валюте. Основной долг показан в валюте счёта."}
                    banking["currency"] = currency
                    banking["note"] = note
                    if banking["is_urgent"] and bal > 0:
                        urgent_cards_count += 1
                    bucket["total_min_payments_cents"] += banking["min_payment_cents"]
                    if currency == "RUB":
                        total_min_payments_cents += banking["min_payment_cents"]
                else:
                    bucket["loans_debt_cents"] += bal
                    if currency == "RUB":
                        loans_debt_cents += bal
                    avail_cents = 0

                if currency == "RUB":
                    total_debt_cents += bal

                debts.append({
                    "id": r["id"],
                    "code": r["code"],
                    "name": r["name"],
                    "subtype": subtype,
                    "currency": currency,
                    "debt_cents": bal,
                    "debt_rub": cents_to_rubles(bal),
                    "credit_balance_cents": max(0, -r["balance_cents"]),
                    "credit_balance_rub": cents_to_rubles(max(0, -r["balance_cents"])),
                    "credit_limit_cents": limit,
                    "credit_limit_rub": cents_to_rubles(limit),
                    "available_cents": avail_cents,
                    "available_rub": cents_to_rubles(avail_cents),
                    "description": r["description"],
                    "banking": banking,
                    "linked_obligation": ob_by_acc.get(r["id"])
                })

            return {
                "debts": debts,
                "totals_currency": "RUB",
                "totals_by_currency": totals_by_currency,
                "total_debt_cents": total_debt_cents,
                "total_debt_rub": cents_to_rubles(total_debt_cents),
                "credit_cards_debt_cents": credit_cards_debt_cents,
                "credit_cards_debt_rub": cents_to_rubles(credit_cards_debt_cents),
                "loans_debt_cents": loans_debt_cents,
                "loans_debt_rub": cents_to_rubles(loans_debt_cents),
                "has_urgent_card_payment": urgent_cards_count > 0,
                "urgent_cards_count": urgent_cards_count,
                "total_min_payments_cents": total_min_payments_cents,
                "total_min_payments_rub": cents_to_rubles(total_min_payments_cents)
            }
        finally:
            self._close_if_local(conn)

    @atomic_operation
    def record_debt_repayment(
        self, source_account_id: str, liability_account_id: str, amount_cents: int,
        description: Optional[str] = None, obligation_id: Optional[str] = None,
        member_id: Optional[str] = None, idempotency_key: Optional[str] = None,
        category_id: Optional[str] = None
    ) -> str:
        """Atomically repay principal and link its unique payment to a month."""
        from family_finances_os.models import require_cents
        require_cents(amount_cents)
        source = self.get_account_by_id(source_account_id)
        liability = self.get_account_by_id(liability_account_id)
        if not source or source.account_type != "ASSET" or not source.is_active:
            raise ValueError("Счёт списания должен быть активным счётом активов.")
        if not liability or liability.account_type != "LIABILITY" or not liability.is_active:
            raise ValueError("Счёт задолженности должен быть активным обязательством.")
        if source.currency != liability.currency:
            raise ValueError("Погашение между разными валютами без модели обмена запрещено.")
        conn = self._get_conn()
        cursor = conn.cursor()
        try:
            if member_id:
                cursor.execute("SELECT id FROM members WHERE id = ?;", (member_id,))
                if not cursor.fetchone():
                    raise ValueError("Участник не найден.")
            if obligation_id:
                cursor.execute("SELECT payment_account_id FROM obligations WHERE id = ? AND is_active = 1;", (obligation_id,))
                obligation = cursor.fetchone()
                if not obligation:
                    raise ValueError("Обязательный платёж не найден.")
                if obligation["payment_account_id"] not in (None, liability.id):
                    raise ValueError("Обязательный платёж относится к другой задолженности.")
            cat = category_id or DEBT_CATEGORY_MAP.get(liability.subtype, "cat_debts")
            if category_id:
                cursor.execute("SELECT id FROM categories WHERE id = ? AND category_type = 'EXPENSE' AND is_active = 1;", (cat,))
                if not cursor.fetchone():
                    raise ValueError("Категория погашения не найдена.")
            else:
                cursor.execute("INSERT OR IGNORE INTO categories (id, name, category_type, parent_id, icon, sort_order, is_active) VALUES ('cat_debts', 'Кредиты, долги и займы', 'EXPENSE', NULL, '💳', 80, 1);")
                cursor.execute("INSERT OR IGNORE INTO categories (id, name, category_type, parent_id, icon, sort_order, is_active) VALUES (?, 'Погашение задолженности', 'EXPENSE', 'cat_debts', '💳', 81, 1);", (cat,))
            existing = None
            if idempotency_key:
                cursor.execute("SELECT id, tx_date FROM transactions WHERE idempotency_key = ?;", (idempotency_key,))
                existing = cursor.fetchone()
            txid = generate_uuid()
            tx = Transaction(id=txid,
                tx_date=existing["tx_date"] if existing else current_iso_time()[:10],
                tx_type="CREDIT_PAYMENT" if liability.subtype == "CREDIT_CARD" else "LOAN_REPAYMENT",
                description=description.strip() if description and description.strip() else f"Погашение: {liability.name}",
                created_by_member_id=member_id,
                postings=[Posting(id=generate_uuid(),transaction_id=txid,account_id=liability.id,
                                  amount_cents=amount_cents,posting_type="DEBIT",ownership_scope=liability.ownership_scope,
                                  purpose_allocation="SAFE_TO_SPEND",category_id=cat),
                          Posting(id=generate_uuid(),transaction_id=txid,account_id=source.id,
                                  amount_cents=amount_cents,posting_type="CREDIT",ownership_scope=source.ownership_scope,
                                  purpose_allocation="SAFE_TO_SPEND",category_id=cat)])
            if not existing:
                debt = self.get_account_balance_cents(liability.id)
                if amount_cents > max(0, debt):
                    raise ValueError("Платёж превышает текущий долг. Переплата не поддерживается.")
                if amount_cents > self.get_account_balance_cents(source.id):
                    raise ValueError("На счёте списания недостаточно средств.")
            saved_id = self.record_transaction(tx, idempotency_key=idempotency_key)
            if obligation_id:
                self.mark_obligation_paid(obligation_id=obligation_id, month_year=tx.tx_date[:7],
                                          transaction_id=saved_id, paid_amount_cents=amount_cents)
            return saved_id
        finally:
            self._close_if_local(conn)

    # ---------------------------------------------------------

    # 10. Smart Quick Input (Stage 9 Frictionless Entry)

    # ---------------------------------------------------------

    def parse_quick_input(self, text: str) -> Dict[str, Any]:

        """

        Intelligently parse natural input like '500 кофе', '1500 продукты', '80000 зарплата'.

        Extracts amount, transaction type, description, and best matching category.

        """

        import re

        if not text or not text.strip():

            raise ValueError("Текст операции не может быть пустым.")

        clean_text = text.strip()

        # Find amount: integer or decimal with . or ,

        amount_match = re.search(r'(?:^|\s)(\d+(?:[\s_]\d{3})*(?:[.,]\d{1,2})?|\d+(?:[.,]\d{1,2})?)(?:\s*₽|\s*руб)?(?:\s|$)', clean_text, re.IGNORECASE)

        if not amount_match:

            raise ValueError("Не удалось распознать сумму в строке ввода. Укажите число, например: '500 кофе'.")

        raw_num = amount_match.group(1).replace(" ", "").replace("_", "").replace(",", ".")

        amount_cents = rubles_to_cents(raw_num)

        if amount_cents <= 0:

            raise ValueError("Сумма операции должна быть больше нуля.")

        # Remove amount from text to get description

        desc_part = clean_text[:amount_match.start()] + clean_text[amount_match.end():]

        desc_part = re.sub(r'\s+', ' ', desc_part).strip(' -:•₽р.')

        if not desc_part:

            desc_part = "Расход"

        desc_lower = desc_part.lower()

        income_words = ["зарплата", "аванс", "премия", "доход", "поступление", "получка", "дивиденды", "кэшбэк", "кешбэк", "бонус"]

        is_income = any(w in desc_lower for w in income_words)

        tx_type = "INCOME" if is_income else "EXPENSE"

        cat_search_terms = [

            ("%Кафе%", ["кофе", "кафе", "ресторан", "обед", "ужин", "завтрак", "бургер", "додо", "пицца", "макдак", "вкусно", "столовая", "бар", "кулинария", "доставка", "суши"]),

            ("%Продукт%", ["продукт", "супермаркет", "пятерочк", "магнит", "перекресток", "вкусвилл", "еда", "хлеб", "молоко", "мясо", "сыр", "овощи", "фрукты", "магазин", "ашан", "лента"]),

            ("%Такси%", ["такси", "каршеринг"]),

            ("%Бензин%", ["бензин", "заправка", "лукойл", "газпром", "роснефть"]),

            ("%Транспорт%", ["метро", "проезд", "автобус", "парковка", "автомойка", "шиномонтаж", "сто", "авто"]),

            ("%Аптек%", ["аптек", "лекарств", "витамин", "таблетк"]),

            ("%Врач%", ["врач", "клиник", "анализ", "доктор", "больниц", "оптика"]),

            ("%Стоматолог%", ["стоматолог", "зуб"]),

            ("%ЖКХ%", ["жкх", "квартплата", "свет", "вода", "газ", "отопление", "домофон", "тсж"]),

            ("%Интернет%", ["интернет", "связь", "мтс", "мегафон", "билайн", "теле2", "т-мобайл", "телефон"]),

            ("%Аренда%", ["аренда", "ипотека"]),

            ("%Одежда%", ["одежд", "обувь", "wildberries", "вайлдберриз", "ozon", "озон", "куртка", "джинсы", "кроссовк", "ботинк"]),

            ("%Кино%", ["кино", "театр", "концерт"]),

            ("%Подписк%", ["подписк", "яндекс плюс"]),

            ("%Зарплат%", ["зарплата", "аванс", "премия", "получка", "оклад", "доход"]),

            ("%Пассивный%", ["проценты", "дивиденды", "вклад", "инвестиции", "кэшбэк", "кешбэк"])

        ]

        matched_search_pattern = None

        for pattern, kw_list in cat_search_terms:

            if any(kw in desc_lower for kw in kw_list):

                matched_search_pattern = pattern

                break

        matched_cat_name = None

        matched_cat_id = None

        conn = self._get_conn()

        cursor = conn.cursor()

        try:

            if matched_search_pattern:

                cursor.execute("SELECT id, name FROM categories WHERE name LIKE ? AND is_active = 1 LIMIT 1;", (matched_search_pattern,))

                cat_row = cursor.fetchone()

                if cat_row:

                    matched_cat_id = cat_row["id"]

                    matched_cat_name = cat_row["name"]

            if not matched_cat_id:

                cursor.execute("SELECT id, name FROM categories WHERE is_active = 1 AND category_type = ?;", (tx_type,))

                all_cats = cursor.fetchall()

                for c in all_cats:

                    if c["name"].lower() in desc_lower or desc_lower in c["name"].lower():

                        matched_cat_id = c["id"]

                        matched_cat_name = c["name"]

                        break

            if not matched_cat_id:

                if tx_type == "INCOME":

                    cursor.execute("SELECT id, name FROM categories WHERE category_type = 'INCOME' AND is_active = 1 LIMIT 1;")

                else:

                    cursor.execute("SELECT id, name FROM categories WHERE category_type = 'EXPENSE' AND is_active = 1 ORDER BY sort_order ASC LIMIT 1;")

                def_cat = cursor.fetchone()

                if def_cat:

                    matched_cat_id = def_cat["id"]

                    matched_cat_name = def_cat["name"]

            cursor.execute("SELECT id, name, code FROM accounts WHERE code = '1010' AND is_active = 1;")

            def_acc = cursor.fetchone()

            if not def_acc:

                cursor.execute("SELECT id, name, code FROM accounts WHERE account_type = 'ASSET' AND subtype = 'DEBIT_CARD' AND is_active = 1 LIMIT 1;")

                def_acc = cursor.fetchone()

            default_acc_id = def_acc["id"] if def_acc else None

            default_acc_name = def_acc["name"] if def_acc else None

        finally:

            self._close_if_local(conn)

        capitalized_desc = desc_part[0].upper() + desc_part[1:] if desc_part else ("Доход" if is_income else "Расход")

        return {

            "raw_text": text,

            "amount_cents": amount_cents,

            "amount_rub": cents_to_rubles(amount_cents),

            "description": capitalized_desc,

            "tx_type": tx_type,

            "category_id": matched_cat_id,

            "category_name": matched_cat_name or ("Основная зарплата" if is_income else "Прочие расходы"),

            "default_account_id": default_acc_id,

            "default_account_name": default_acc_name

        }

    def record_quick_input(

        self,

        text: str,

        account_id: Optional[str] = None,

        category_id: Optional[str] = None,

        member_id: Optional[str] = None,

        idempotency_key: Optional[str] = None

    ) -> str:

        """

        Parse and immediately record a transaction from single-string natural input.

        """

        parsed = self.parse_quick_input(text)

        acc_id = account_id or parsed["default_account_id"]

        if not acc_id:

            raise ValueError("Не найден счет списания/зачисления по умолчанию.")

        acc = self.get_account_by_id(acc_id)

        if not acc:

            raise ValueError(f"Счет {acc_id} не найден.")

        cat_id = category_id or parsed["category_id"]

        cat_acc_id = None

        conn = self._get_conn()

        cursor = conn.cursor()

        try:

            if parsed["tx_type"] == "INCOME":

                cursor.execute("SELECT id FROM accounts WHERE account_type = 'INCOME' AND is_active = 1 LIMIT 1;")

            else:

                cursor.execute("SELECT id FROM accounts WHERE account_type = 'EXPENSE' AND is_active = 1 LIMIT 1;")

            acc_row = cursor.fetchone()

            if acc_row:

                cat_acc_id = acc_row["id"]

        finally:

            self._close_if_local(conn)

        if not cat_acc_id:

            cat_acc_id = "acc_core_5010" if parsed["tx_type"] == "EXPENSE" else "acc_core_4010"

        tx_id = generate_uuid()

        tx_date = current_iso_time()[:10]

        amount_cents = parsed["amount_cents"]

        desc = parsed["description"]

        postings = []

        if parsed["tx_type"] == "EXPENSE":

            postings.append(Posting(

                id=generate_uuid(), transaction_id=tx_id, account_id=cat_acc_id,

                amount_cents=amount_cents, posting_type="DEBIT", ownership_scope=acc.ownership_scope,

                category_id=cat_id

            ))

            postings.append(Posting(

                id=generate_uuid(), transaction_id=tx_id, account_id=acc.id,

                amount_cents=amount_cents, posting_type="CREDIT", ownership_scope=acc.ownership_scope

            ))

        else:

            postings.append(Posting(

                id=generate_uuid(), transaction_id=tx_id, account_id=acc.id,

                amount_cents=amount_cents, posting_type="DEBIT", ownership_scope=acc.ownership_scope

            ))

            postings.append(Posting(

                id=generate_uuid(), transaction_id=tx_id, account_id=cat_acc_id,

                amount_cents=amount_cents, posting_type="CREDIT", ownership_scope=acc.ownership_scope,

                category_id=cat_id

            ))

        tx = Transaction(

            id=tx_id, tx_date=tx_date, tx_type=parsed["tx_type"], description=desc,

            created_by_member_id=member_id,

            idempotency_key=idempotency_key, postings=postings

        )

        return self.record_transaction(tx)

    # ---------------------------------------------------------

    # 13. Savings Envelopes & Virtual Piggy Banks (Конверты-копилки)

    # ---------------------------------------------------------

    @atomic_operation
    def create_envelope(

        self,

        name: str,

        target_amount_cents: int = 0,

        icon: str = "✉️",

        color: str = "#3b82f6",

        linked_account_id: Optional[str] = None,

        category_id: Optional[str] = None,

        note: Optional[str] = None,

        initial_amount_cents: int = 0

    ) -> Envelope:

        """Create a new savings envelope / piggy bank."""

        self._reservation_cents(target_amount_cents, allow_zero=True)
        self._reservation_cents(initial_amount_cents, allow_zero=True)

        if not name or not name.strip():

            raise ValueError("Название конверта-копилки не может быть пустым.")

        if target_amount_cents < 0:

            raise ValueError("Целевая сумма конверта не может быть отрицательной.")

        if initial_amount_cents < 0:

            raise ValueError("Начальная сумма конверта не может быть отрицательной.")

        env_id = generate_uuid()

        conn = self._get_conn()

        cursor = conn.cursor()

        try:

            self._reservation_account(cursor, linked_account_id)
            self._reservation_reference(cursor, "categories", category_id)

            cursor.execute("""

            INSERT INTO envelopes (id, name, target_amount_cents, current_amount_cents, icon, color, linked_account_id, category_id, note, is_active)

            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1);

            """, (env_id, name.strip(), target_amount_cents, initial_amount_cents, icon, color, linked_account_id, category_id, note))

            payload = {

                "id": env_id,

                "name": name.strip(),

                "target_amount_cents": target_amount_cents,

                "current_amount_cents": initial_amount_cents,

                "icon": icon,

                "color": color,

                "linked_account_id": linked_account_id,

                "category_id": category_id,

                "note": note,

                "is_active": 1,

                "created_at": current_iso_time()

            }

            from .reservation_events import ensure_baseline
            ensure_baseline(cursor, "ENVELOPE", env_id, base_cents=0)
            self._get_sync_engine().record_change_event("ENVELOPE", env_id, "INSERT", payload, cursor=cursor)

            if initial_amount_cents > 0:

                self._envelope_operation(cursor, env_id, "DEPOSIT", initial_amount_cents,
                                         note="Начальный остаток копилки")

            self._commit(conn)

            self._save_if_encrypted()

            return Envelope(

                id=env_id,

                name=name.strip(),

                target_amount_cents=target_amount_cents,

                current_amount_cents=initial_amount_cents,

                icon=icon,

                color=color,

                linked_account_id=linked_account_id,

                category_id=category_id,

                note=note

            )

        finally:

            self._close_if_local(conn)

    def get_envelope(self, envelope_id: str) -> Optional[Dict[str, Any]]:
        """Get single envelope by id."""
        conn = self._get_conn()
        cursor = conn.cursor()
        try:
            cursor.execute("""
            SELECT e.*, a.name as linked_account_name, a.code as linked_account_code, c.name as category_name
            FROM envelopes e
            LEFT JOIN accounts a ON e.linked_account_id = a.id
            LEFT JOIN categories c ON e.category_id = c.id
            WHERE e.id = ? AND e.is_active = 1;
            """, (envelope_id,))
            r = cursor.fetchone()
            if not r:
                return None
            target_cents = r["target_amount_cents"]
            current_cents = r["current_amount_cents"]
            rem_cents = max(0, target_cents - current_cents)
            pct = round((current_cents / target_cents) * 100, 1) if target_cents > 0 else (100.0 if current_cents > 0 else 0.0)
            return {
                "id": r["id"],
                "name": r["name"],
                "target_amount_cents": target_cents,
                "target_amount_rub": cents_to_rubles(target_cents),
                "current_amount_cents": current_cents,
                "current_amount_rub": cents_to_rubles(current_cents),
                "remaining_cents": rem_cents,
                "remaining_rub": cents_to_rubles(rem_cents),
                "progress_percent": min(100.0, pct),
                "icon": r["icon"],
                "color": r["color"],
                "linked_account_id": r["linked_account_id"],
                "linked_account_name": r["linked_account_name"],
                "currency": "RUB",
                "tracking_mode": "INFORMATIONAL",
                "category_id": r["category_id"],
                "category_name": r["category_name"],
                "note": r["note"]
            }
        finally:
            self._close_if_local(conn)

    @atomic_operation
    def update_envelope(
        self,
        envelope_id: str,
        name: Optional[str] = None,
        target_amount_cents: Optional[int] = None,
        icon: Optional[str] = None,
        color: Optional[str] = None,
        linked_account_id: Optional[str] = None,
        category_id: Optional[str] = None,
        note: Optional[str] = None,
        current_amount_cents: Optional[int] = None
    ) -> bool:
        """Update envelope parameters and optionally adjust balance."""
        conn = self._get_conn()
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT * FROM envelopes WHERE id = ? AND is_active = 1;", (envelope_id,))
            env_row = cursor.fetchone()
            if not env_row:
                return False

            updates = []
            params = []
            if name is not None:
                if not name.strip():
                    raise ValueError("Название конверта не может быть пустым.")
                updates.append("name = ?")
                params.append(name.strip())
            if target_amount_cents is not None:
                self._reservation_cents(target_amount_cents, allow_zero=True)
                updates.append("target_amount_cents = ?")
                params.append(target_amount_cents)
            if icon is not None:
                updates.append("icon = ?")
                params.append(icon)
            if color is not None:
                updates.append("color = ?")
                params.append(color)
            if linked_account_id is not None:
                self._reservation_account(cursor, linked_account_id or None)
                updates.append("linked_account_id = ?")
                params.append(linked_account_id or None)
            if category_id is not None:
                self._reservation_reference(cursor, "categories", category_id or None)
                updates.append("category_id = ?")
                params.append(category_id or None)
            if note is not None:
                updates.append("note = ?")
                params.append(note.strip() if note else None)

            if current_amount_cents is not None:
                self._reservation_cents(current_amount_cents, allow_zero=True)
                new_bal = current_amount_cents
                old_bal = env_row["current_amount_cents"]
                if new_bal != old_bal:
                    updates.append("current_amount_cents = ?")
                    params.append(new_bal)
                    diff = new_bal - old_bal
                    op_type = "DEPOSIT" if diff > 0 else "WITHDRAW"
                    self._envelope_operation(cursor, envelope_id, op_type, abs(diff),
                                             note="Корректировка баланса конверта")

            if updates:
                params.append(envelope_id)
                cursor.execute(f"UPDATE envelopes SET {', '.join(updates)} WHERE id = ? AND is_active = 1;", tuple(params))
                cursor.execute("SELECT * FROM envelopes WHERE id = ?;", (envelope_id,))
                row = cursor.fetchone()
                if row:
                    self._get_sync_engine().record_change_event("ENVELOPE", envelope_id, "UPDATE", dict(row), cursor=cursor)

            self._commit(conn)
            self._save_if_encrypted()
            return True
        finally:
            self._close_if_local(conn)

    @atomic_operation
    def archive_envelope(self, envelope_id: str) -> bool:

        """Archive an envelope (soft-delete)."""

        conn = self._get_conn()

        cursor = conn.cursor()

        try:

            cursor.execute("UPDATE envelopes SET is_active = 0 WHERE id = ?;", (envelope_id,))

            changed = cursor.rowcount > 0

            if changed:

                self._reservation_snapshot(cursor, "envelopes", envelope_id, "ENVELOPE")

            self._commit(conn)

            self._save_if_encrypted()

            return changed

        finally:

            self._close_if_local(conn)

    def get_envelopes(self, active_only: bool = True) -> List[Dict[str, Any]]:

        """List savings envelopes / piggy banks."""

        conn = self._get_conn()

        cursor = conn.cursor()

        try:

            where_sql = "WHERE e.is_active = 1" if active_only else ""

            cursor.execute(f"""

            SELECT e.*, a.name as linked_account_name, a.code as linked_account_code, c.name as category_name

            FROM envelopes e

            LEFT JOIN accounts a ON e.linked_account_id = a.id

            LEFT JOIN categories c ON e.category_id = c.id

            {where_sql}

            ORDER BY e.created_at ASC;

            """)

            rows = cursor.fetchall()

            res = []

            for r in rows:

                target_cents = r["target_amount_cents"]

                current_cents = r["current_amount_cents"]

                rem_cents = max(0, target_cents - current_cents)

                if target_cents > 0:

                    pct = round((current_cents / target_cents) * 100, 1)

                    pct = min(100.0, pct)

                else:

                    pct = 100.0 if current_cents > 0 else 0.0

                res.append({

                    "id": r["id"],

                    "name": r["name"],

                    "target_amount_cents": target_cents,

                    "target_amount_rub": cents_to_rubles(target_cents),

                    "current_amount_cents": current_cents,

                    "current_amount_rub": cents_to_rubles(current_cents),

                    "remaining_cents": rem_cents,

                    "remaining_rub": cents_to_rubles(rem_cents),

                    "progress_percent": pct,

                    "icon": r["icon"] or "✉️",

                    "color": r["color"] or "#3b82f6",

                    "linked_account_id": r["linked_account_id"],

                    "linked_account_name": r["linked_account_name"],
                "currency": "RUB",
                "tracking_mode": "INFORMATIONAL",

                    "category_id": r["category_id"],

                    "category_name": r["category_name"],

                    "note": r["note"],

                    "is_active": bool(r["is_active"]),

                    "created_at": r["created_at"]

                })

            return res

        finally:

            self._close_if_local(conn)

    def get_envelopes_summary(self) -> Dict[str, Any]:

        """Aggregate summary of all envelopes (total saved, active count, envelopes list)."""

        envelopes = self.get_envelopes()

        total_cents = sum(e["current_amount_cents"] for e in envelopes)

        target_cents = sum(e["target_amount_cents"] for e in envelopes)

        return {

            "envelopes": envelopes,

            "count": len(envelopes),
            "currency": "RUB",
            "tracking_mode": "INFORMATIONAL",
            "included_in_safe_to_spend": False,

            "total_saved_cents": total_cents,

            "total_saved_rub": cents_to_rubles(total_cents),

            "total_target_cents": target_cents,

            "total_target_rub": cents_to_rubles(target_cents)

        }

    @atomic_operation
    def deposit_to_envelope(

        self,

        envelope_id: str,

        amount_cents: int,

        source_account_id: Optional[str] = None,

        note: Optional[str] = None,

        member_id: Optional[str] = None,

        idempotency_key: Optional[str] = None

    ) -> Dict[str, Any]:

        """Put money into a savings envelope (положить в копилку)."""

        self._reservation_cents(amount_cents)

        if amount_cents <= 0:

            raise ValueError("Сумма пополнения конверта должна быть больше нуля.")

        conn = self._get_conn()

        cursor = conn.cursor()

        try:

            request = self._reservation_request(cursor,"envelope-deposit",idempotency_key,
                [envelope_id,amount_cents,source_account_id,note,member_id])
            if request[2] is not None:
                return request[2]

            cursor.execute("SELECT * FROM envelopes WHERE id = ? AND is_active = 1;", (envelope_id,))

            env = cursor.fetchone()

            if not env:

                raise ValueError("Конверт-копилка не найден.")

            self._reservation_account(cursor, source_account_id)
            self._reservation_account(cursor, env["linked_account_id"])
            self._reservation_reference(cursor, "members", member_id)
            if (source_account_id and env["linked_account_id"]
                    and source_account_id != env["linked_account_id"]
                    and self.get_account_balance_cents(source_account_id) < amount_cents):
                raise ValueError("Недостаточно средств на исходном счёте.")

            new_balance = env["current_amount_cents"] + amount_cents
            self._reservation_cents(new_balance, allow_zero=True)

            cursor.execute("UPDATE envelopes SET current_amount_cents = ? WHERE id = ?;", (new_balance, envelope_id))

            op_id = self._envelope_operation(cursor, envelope_id, "DEPOSIT", amount_cents,
                                     source_account_id=source_account_id, note=note, member_id=member_id,
                                     operation_id=("envelope-operation-v1:" + request[0].rsplit(":",1)[1]) if request[0] else None, emit=False)

            # Record CDC

            cursor.execute("SELECT * FROM envelopes WHERE id = ?;", (envelope_id,))

            updated_env = cursor.fetchone()

            self._get_sync_engine().record_change_event("ENVELOPE", envelope_id, "UPDATE", dict(updated_env), cursor=cursor)

            # Optional double-entry transfer if source and linked destination exist and differ

            tx_id = None

            if source_account_id and env["linked_account_id"] and source_account_id != env["linked_account_id"]:

                tx_id = self.record_transfer(

                    from_account_id=source_account_id,

                    to_account_id=env["linked_account_id"],

                    amount_cents=amount_cents,

                    description=f"Пополнение конверта-копилки '{env['name']}'",

                    created_by_member_id=member_id,

                    idempotency_key=("envelope-bank-v1:" + request[0].rsplit(":",1)[1]) if request[0] else None

                )

            from .reservation_events import register_operation
            register_operation(cursor, op_id, tx_id)
            self._reservation_snapshot(cursor, "envelope_operations", op_id, "ENVELOPE_OPERATION", "INSERT")

            self._commit(conn)

            self._save_if_encrypted()

            return self._reservation_result(cursor, request, {

                "status": "success",

                "envelope_id": envelope_id,

                "amount_rub": cents_to_rubles(amount_cents),

                "new_balance_rub": cents_to_rubles(new_balance),

                "transaction_id": tx_id

            })

        finally:

            self._close_if_local(conn)

    @atomic_operation
    def withdraw_from_envelope(

        self,

        envelope_id: str,

        amount_cents: int,

        destination_account_id: Optional[str] = None,

        note: Optional[str] = None,

        member_id: Optional[str] = None,

        idempotency_key: Optional[str] = None

    ) -> Dict[str, Any]:

        """Take money out of a savings envelope (взять из копилки / потратить)."""

        self._reservation_cents(amount_cents)

        if amount_cents <= 0:

            raise ValueError("Сумма списания из конверта должна быть больше нуля.")

        conn = self._get_conn()

        cursor = conn.cursor()

        try:

            request = self._reservation_request(cursor,"envelope-withdraw",idempotency_key,
                [envelope_id,amount_cents,destination_account_id,note,member_id])
            if request[2] is not None:
                return request[2]

            cursor.execute("SELECT * FROM envelopes WHERE id = ? AND is_active = 1;", (envelope_id,))

            env = cursor.fetchone()

            if not env:

                raise ValueError("Конверт-копилка не найден.")

            self._reservation_account(cursor, destination_account_id)
            self._reservation_account(cursor, env["linked_account_id"])
            self._reservation_reference(cursor, "members", member_id)
            if (destination_account_id and env["linked_account_id"]
                    and destination_account_id != env["linked_account_id"]
                    and self.get_account_balance_cents(env["linked_account_id"]) < amount_cents):
                raise ValueError("Недостаточно средств на связанном счёте конверта.")

            if env["current_amount_cents"] < amount_cents:

                raise ValueError(f"Недостаточно средств в конверте '{env['name']}'. Доступно: {cents_to_rubles(env['current_amount_cents'])} ₽.")

            new_balance = env["current_amount_cents"] - amount_cents

            cursor.execute("UPDATE envelopes SET current_amount_cents = ? WHERE id = ?;", (new_balance, envelope_id))

            op_id = self._envelope_operation(cursor, envelope_id, "WITHDRAW", amount_cents,
                                     destination_account_id=destination_account_id, note=note, member_id=member_id,
                                     operation_id=("envelope-operation-v1:" + request[0].rsplit(":",1)[1]) if request[0] else None, emit=False)

            # Record CDC

            cursor.execute("SELECT * FROM envelopes WHERE id = ?;", (envelope_id,))

            updated_env = cursor.fetchone()

            self._get_sync_engine().record_change_event("ENVELOPE", envelope_id, "UPDATE", dict(updated_env), cursor=cursor)

            # Optional double-entry transfer back to destination account

            tx_id = None

            if destination_account_id and env["linked_account_id"] and destination_account_id != env["linked_account_id"]:

                tx_id = self.record_transfer(

                    from_account_id=env["linked_account_id"],

                    to_account_id=destination_account_id,

                    amount_cents=amount_cents,

                    description=f"Изъятие из конверта-копилки '{env['name']}'",

                    created_by_member_id=member_id,

                    idempotency_key=("envelope-bank-v1:" + request[0].rsplit(":",1)[1]) if request[0] else None

                )

            from .reservation_events import register_operation
            register_operation(cursor, op_id, tx_id)
            self._reservation_snapshot(cursor, "envelope_operations", op_id, "ENVELOPE_OPERATION", "INSERT")

            self._commit(conn)

            self._save_if_encrypted()

            return self._reservation_result(cursor, request, {

                "status": "success",

                "envelope_id": envelope_id,

                "amount_rub": cents_to_rubles(amount_cents),

                "new_balance_rub": cents_to_rubles(new_balance),

                "transaction_id": tx_id

            })

        finally:

            self._close_if_local(conn)

    @atomic_operation
    def transfer_between_envelopes(

        self,

        from_envelope_id: str,

        to_envelope_id: str,

        amount_cents: int,

        note: Optional[str] = None,

        member_id: Optional[str] = None,

        idempotency_key: Optional[str] = None

    ) -> Dict[str, Any]:

        """Transfer money from one envelope to another (переложить между конвертами)."""

        self._reservation_cents(amount_cents)

        if amount_cents <= 0:

            raise ValueError("Сумма перевода должна быть больше нуля.")

        if from_envelope_id == to_envelope_id:

            raise ValueError("Нельзя перевести средства в тот же самый конверт.")

        conn = self._get_conn()

        cursor = conn.cursor()

        try:

            request = self._reservation_request(cursor,"envelope-transfer",idempotency_key,
                [from_envelope_id,to_envelope_id,amount_cents,note,member_id])
            if request[2] is not None:
                return request[2]

            cursor.execute("SELECT * FROM envelopes WHERE id = ? AND is_active = 1;", (from_envelope_id,))

            env_from = cursor.fetchone()

            cursor.execute("SELECT * FROM envelopes WHERE id = ? AND is_active = 1;", (to_envelope_id,))

            env_to = cursor.fetchone()

            if not env_from or not env_to:

                raise ValueError("Один из указанных конвертов не найден.")

            self._reservation_reference(cursor, "members", member_id)
            self._reservation_account(cursor, env_from["linked_account_id"])
            self._reservation_account(cursor, env_to["linked_account_id"])
            if env_from["linked_account_id"] != env_to["linked_account_id"]:
                raise ValueError("Для перекладывания выберите конверты на одном связанном счёте либо оба без привязки. Денежный перевод выполняется отдельно.")

            if env_from["current_amount_cents"] < amount_cents:

                raise ValueError(f"Недостаточно средств в конверте '{env_from['name']}'. Доступно: {cents_to_rubles(env_from['current_amount_cents'])} ₽.")

            new_from_balance = env_from["current_amount_cents"] - amount_cents

            new_to_balance = env_to["current_amount_cents"] + amount_cents
            self._reservation_cents(new_to_balance, allow_zero=True)

            cursor.execute("UPDATE envelopes SET current_amount_cents = ? WHERE id = ?;", (new_from_balance, from_envelope_id))

            cursor.execute("UPDATE envelopes SET current_amount_cents = ? WHERE id = ?;", (new_to_balance, to_envelope_id))

            self._envelope_operation(cursor, from_envelope_id, "TRANSFER", amount_cents,
                                     target_envelope_id=to_envelope_id, note=note, member_id=member_id,
                                     operation_id=("envelope-operation-v1:" + request[0].rsplit(":",1)[1]) if request[0] else None)

            # Record CDCs

            cursor.execute("SELECT * FROM envelopes WHERE id = ?;", (from_envelope_id,))

            self._get_sync_engine().record_change_event("ENVELOPE", from_envelope_id, "UPDATE", dict(cursor.fetchone()), cursor=cursor)

            cursor.execute("SELECT * FROM envelopes WHERE id = ?;", (to_envelope_id,))

            self._get_sync_engine().record_change_event("ENVELOPE", to_envelope_id, "UPDATE", dict(cursor.fetchone()), cursor=cursor)

            self._commit(conn)

            self._save_if_encrypted()

            return self._reservation_result(cursor, request, {

                "status": "success",

                "from_envelope_id": from_envelope_id,

                "to_envelope_id": to_envelope_id,

                "amount_rub": cents_to_rubles(amount_cents),

                "from_new_balance_rub": cents_to_rubles(new_from_balance),

                "to_new_balance_rub": cents_to_rubles(new_to_balance)

            })

        finally:

            self._close_if_local(conn)

