"""

Family Finances OS - Comprehensive Double-Entry Ledger Engine

Implements Stage 2: Full Account Lifecycle, Internal Transfers, Credit Card Isolation,

Personal-for-Common Expense Tracking, and Multi-Balance Financial Overviews.

"""

import hashlib

import sqlite3

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

def compute_tx_payload_hash(tx: Transaction) -> str:

    """

    Compute a deterministic canonical SHA-256 hash of the transaction payload

    to detect any tampering or parameter mismatch under the same idempotency key.

    """

    postings_repr = sorted([

        (p.account_id, p.amount_cents, p.posting_type, p.ownership_scope)

        for p in tx.postings

    ])

    canonical_str = f"{tx.tx_type}:{tx.description}:{postings_repr}"

    return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()

class LedgerEngine:

    def __init__(self, conn_or_path: Any = None):

        self.conn_or_path = conn_or_path

        self._sync_engine = None

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

        from family_finances_os.db import get_db_connection

        return get_db_connection(self.conn_or_path)

    def _close_if_local(self, conn: sqlite3.Connection):

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

        from family_finances_os.db import GLOBAL_STORAGE

        if GLOBAL_STORAGE.is_unlocked():

            GLOBAL_STORAGE.save()

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

            conn.commit()

            self._save_if_encrypted()

            return account

        finally:

            self._close_if_local(conn)

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

            conn.commit()

            self._save_if_encrypted()

            return cursor.rowcount > 0

        finally:

            self._close_if_local(conn)

    def archive_account(self, account_id: str) -> bool:

        """Soft-archive account by setting is_active = 0."""

        conn = self._get_conn()

        cursor = conn.cursor()

        try:

            cursor.execute("UPDATE accounts SET is_active = 0 WHERE id = ?", (account_id,))

            if cursor.rowcount > 0:

                self._get_sync_engine().record_change_event("ACCOUNT", account_id, "UPDATE", {"id": account_id, "is_active": 0}, cursor=cursor)

            conn.commit()

            self._save_if_encrypted()

            return cursor.rowcount > 0

        finally:

            self._close_if_local(conn)

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

                conn.commit()

                self._save_if_encrypted()

                return True

            return False

        finally:

            self._close_if_local(conn)

    def update_transaction(

        self,

        transaction_id: str,

        tx_date: str = None,

        description: str = None,

        amount_cents: int = None,

        category_id: str = None,

        account_id: str = None,

        tx_type: str = None

    ) -> bool:

        """

        Update an existing non-voided transaction and its postings.

        Preserves double-entry balance: if amount_cents is updated, all postings are updated.

        Allows modifying tx_date to move transaction to past/future months.

        Updates category on expense/income posting and source/destination account on asset/liability posting.

        """

        conn = self._get_conn()

        cursor = conn.cursor()

        try:

            cursor.execute("SELECT * FROM transactions WHERE id = ? AND is_voided = 0;", (transaction_id,))

            tx_row = cursor.fetchone()

            if not tx_row:

                return False

            updates = []

            params = []

            if tx_date:

                updates.append("tx_date = ?")

                params.append(tx_date)

            if description is not None:

                updates.append("description = ?")

                params.append(description)

            if tx_type:

                updates.append("tx_type = ?")

                params.append(tx_type)

            if updates:

                params.append(transaction_id)

                cursor.execute(f"UPDATE transactions SET {', '.join(updates)} WHERE id = ?;", params)

            cursor.execute("SELECT * FROM postings WHERE transaction_id = ?;", (transaction_id,))

            postings = cursor.fetchall()

            current_tx_type = tx_type or tx_row["tx_type"]

            cat_account_id = None

            if category_id:

                cursor.execute("SELECT * FROM categories WHERE id = ?;", (category_id,))

                cat_row = cursor.fetchone()

                if cat_row:

                    cat_acc_code = "5010" if cat_row["category_type"] == "EXPENSE" else "4010"

                    cursor.execute("SELECT id FROM accounts WHERE code = ? LIMIT 1;", (cat_acc_code,))

                    c_acc = cursor.fetchone()

                    if c_acc:

                        cat_account_id = c_acc["id"]

            for p in postings:

                p_id = p["id"]

                p_type = p["posting_type"]

                p_updates = []

                p_params = []

                if amount_cents is not None and amount_cents > 0:

                    p_updates.append("amount_cents = ?")

                    p_params.append(amount_cents)

                if current_tx_type == "EXPENSE":

                    if p_type == "DEBIT":

                        if category_id:

                            p_updates.append("category_id = ?")

                            p_params.append(category_id)

                        if cat_account_id:

                            p_updates.append("account_id = ?")

                            p_params.append(cat_account_id)

                    elif p_type == "CREDIT":

                        if account_id:

                            p_updates.append("account_id = ?")

                            p_params.append(account_id)

                elif current_tx_type == "INCOME":

                    if p_type == "CREDIT":

                        if category_id:

                            p_updates.append("category_id = ?")

                            p_params.append(category_id)

                        if cat_account_id:

                            p_updates.append("account_id = ?")

                            p_params.append(cat_account_id)

                    elif p_type == "DEBIT":

                        if account_id:

                            p_updates.append("account_id = ?")

                            p_params.append(account_id)

                if p_updates:

                    p_params.append(p_id)

                    cursor.execute(f"UPDATE postings SET {', '.join(p_updates)} WHERE id = ?;", p_params)

            self._get_sync_engine().record_change_event(

                "TRANSACTION", transaction_id, "UPDATE",

                {

                    "id": transaction_id,

                    "tx_date": tx_date or tx_row["tx_date"],

                    "description": description if description is not None else tx_row["description"],

                    "amount_cents": amount_cents,

                    "category_id": category_id,

                    "account_id": account_id

                },

                cursor=cursor

            )

            conn.commit()

            self._save_if_encrypted()

            return True

        finally:

            self._close_if_local(conn)

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

    def record_transaction(self, tx: Transaction, idempotency_key: Optional[str] = None) -> str:

        """

        Record a financial transaction with postings inside an atomic SQLite transaction.

        Enforces double-entry equation (Debit == Credit) and checks idempotency payload matching.

        """

        if not tx.validate_double_entry():

            debits = sum(p.amount_cents for p in tx.postings if p.posting_type == "DEBIT")

            credits = sum(p.amount_cents for p in tx.postings if p.posting_type == "CREDIT")

            raise ValueError(f"Double-entry balance check failed! Total Debits: {debits} cents != Total Credits: {credits} cents")

        payload_hash = compute_tx_payload_hash(tx)

        conn = self._get_conn()

        cursor = conn.cursor()

        # Idempotency check with payload verification

        if idempotency_key:

            cursor.execute("SELECT id, payload_hash FROM transactions WHERE idempotency_key = ?", (idempotency_key,))

            existing = cursor.fetchone()

            if existing:

                existing_hash = existing["payload_hash"]

                if existing_hash and existing_hash != payload_hash:

                    self._close_if_local(conn)

                    raise ValueError(

                        f"Конфликт идемпотентности: ключ '{idempotency_key}' уже зарегистрирован "

                        "с другими параметрами операции. Изменение содержимого запрещено."

                    )

                self._close_if_local(conn)

                return existing["id"]

        try:

            # 1. Insert Transaction Header

            cursor.execute("""

            INSERT INTO transactions 

            (id, tx_date, tx_type, description, created_by_member_id, idempotency_key, payload_hash, is_voided, created_at)

            VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)

            """, (tx.id, tx.tx_date, tx.tx_type, tx.description, tx.created_by_member_id, idempotency_key, payload_hash, tx.created_at))

            # 2. Insert Postings

            for p in tx.postings:

                cursor.execute("""

                INSERT INTO postings 

                (id, transaction_id, account_id, amount_cents, posting_type, ownership_scope, purpose_allocation, note, category_id, created_at)

                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)

                """, (p.id, tx.id, p.account_id, p.amount_cents, p.posting_type, p.ownership_scope, p.purpose_allocation, p.note, getattr(p, "category_id", None), current_iso_time()))

            # 3. Log change for peer sync with full transaction snapshot

            tx_payload = {

                "id": tx.id,

                "tx_date": tx.tx_date,

                "tx_type": tx.tx_type,

                "description": tx.description,

                "created_by_member_id": tx.created_by_member_id,

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

            conn.commit()

            self._save_if_encrypted()

            return tx.id

        except sqlite3.IntegrityError as e:

            conn.rollback()

            # If concurrent race condition triggered UNIQUE constraint on idempotency_key:

            if "transactions.idempotency_key" in str(e) and idempotency_key:

                cursor.execute("SELECT id FROM transactions WHERE idempotency_key = ?", (idempotency_key,))

                winner = cursor.fetchone()

                if winner:

                    return winner["id"]

            raise e

        except Exception as e:

            conn.rollback()

            raise e

        finally:

            self._close_if_local(conn)

    # ---------------------------------------------------------

    # 3. Internal Transfers (Stage 2 Requirement 4.3)

    # ---------------------------------------------------------

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

        if amount_cents <= 0:

            raise ValueError("Сумма перевода должна быть строго больше нуля.")

        from_acc = self.get_account_by_id(from_account_id)

        to_acc = self.get_account_by_id(to_account_id)

        if not from_acc:

            raise ValueError(f"Счет списания {from_account_id} не найден.")

        if not to_acc:

            raise ValueError(f"Счет зачисления {to_account_id} не найден.")

        tx_id = generate_uuid()

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

            a.id, a.code, a.name, a.account_type, a.subtype, a.ownership_scope, a.owner_member_id, a.credit_limit_cents, a.is_active,

            COALESCE(SUM(CASE WHEN p.posting_type = 'DEBIT' THEN p.amount_cents ELSE 0 END), 0) AS total_debit,

            COALESCE(SUM(CASE WHEN p.posting_type = 'CREDIT' THEN p.amount_cents ELSE 0 END), 0) AS total_credit

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

        for r in rows:

            acc_type = r["account_type"]

            subtype = r["subtype"]

            scope = r["ownership_scope"]

            limit = r["credit_limit_cents"] or 0

            debit = r["total_debit"]

            credit = r["total_credit"]

            bal = (debit - credit) if acc_type in ("ASSET", "EXPENSE") else (credit - debit)

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

                if subtype == "CREDIT_CARD":

                    debt = max(0, bal)

                    credit_debt_cents += debt

                    total_credit_limit_cents += limit

                    total_liabilities_cents += debt

                elif subtype in ("LOAN", "MORTGAGE"):

                    loan_debt = max(0, bal)

                    loans_debt_cents += loan_debt

                    total_liabilities_cents += loan_debt

            accounts_list.append({

                "id": r["id"],

                "code": r["code"],

                "name": r["name"],

                "type": acc_type,

                "subtype": subtype,

                "scope": scope,

                "owner_member_id": r["owner_member_id"],

                "balance_cents": bal,

                "balance_rub": cents_to_rubles(bal),

                "credit_limit_cents": limit,

                "credit_limit_rub": cents_to_rubles(limit)

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

        cursor.execute("SELECT count(*) FROM categories;")

        count = cursor.fetchone()[0]

        if count > 0:

            self._close_if_local(conn)

            return []

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

            ("cat_other_exp", "Прочие расходы", "EXPENSE", None, "📦", 90),

            # INCOME

            ("cat_salary", "Зарплата и аванс", "INCOME", None, "💼", 10),

            ("cat_salary_husband", "Зарплата Муж", "INCOME", "cat_salary", "👨", 11),

            ("cat_salary_wife", "Зарплата Жена", "INCOME", "cat_salary", "👩", 12),

            ("cat_freelance", "Подработка и проекты", "INCOME", None, "💻", 20),

            ("cat_passive", "Пассивный доход", "INCOME", None, "📈", 30),

            ("cat_passive_interest", "Проценты по вкладам и счетам", "INCOME", "cat_passive", "💰", 31),

            ("cat_passive_cashback", "Кэшбэк и бонусы банков", "INCOME", "cat_passive", "💳", 32),

            ("cat_other_inc", "Подарки и прочие поступления", "INCOME", None, "🎁", 40),

        ]

        created_ids = []

        for cid, name, ctype, pid, icon, sort_order in categories:

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

            conn.commit()

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

            conn.commit()

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

            conn.commit()

            self._save_if_encrypted()

            return cursor.rowcount > 0

        finally:

            self._close_if_local(conn)

    # ---------------------------------------------------------

    # 7. Fixed Obligations & Monthly Payment Tracking (Stage 3 Requirement 2)

    # ---------------------------------------------------------

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

        if amount_cents <= 0:

            raise ValueError("Сумма обязательства должна быть больше нуля.")

        if not (1 <= due_day <= 31):

            raise ValueError("День списания должен быть от 1 до 31.")

        obl_id = generate_uuid()

        conn = self._get_conn()

        cursor = conn.cursor()

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

            conn.commit()

            self._save_if_encrypted()

            return Obligation(id=obl_id, name=name.strip(), amount_cents=amount_cents, due_day=due_day, category_id=category_id, payment_account_id=payment_account_id, note=note)

        finally:

            self._close_if_local(conn)

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

                if amount_cents <= 0: raise ValueError("Сумма должна быть больше нуля.")

                updates.append("amount_cents = ?")

                params.append(amount_cents)

            if due_day is not None:

                if not (1 <= due_day <= 31): raise ValueError("День списания от 1 до 31.")

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

            conn.commit()

            self._save_if_encrypted()

            return cursor.rowcount > 0

        finally:

            self._close_if_local(conn)

    def archive_obligation(self, obligation_id: str) -> bool:

        """Soft-archive obligation."""

        conn = self._get_conn()

        cursor = conn.cursor()

        try:

            cursor.execute("UPDATE obligations SET is_active = 0 WHERE id = ?;", (obligation_id,))

            if cursor.rowcount > 0:

                self._get_sync_engine().record_change_event("OBLIGATION", obligation_id, "UPDATE", {"id": obligation_id, "is_active": 0}, cursor=cursor)

            conn.commit()

            self._save_if_encrypted()

            return cursor.rowcount > 0

        finally:

            self._close_if_local(conn)

    def get_obligations(self, month_year: Optional[str] = None) -> List[Dict[str, Any]]:

        """

        Get all active obligations with monthly payment fulfillment status.

        """

        if not month_year:

            from datetime import datetime

            month_year = datetime.now().strftime("%Y-%m")

        conn = self._get_conn()

        cursor = conn.cursor()

        cursor.execute("""

        SELECT 

            o.id, o.name, o.amount_cents, o.due_day, o.note, o.category_id, o.payment_account_id,

            c.name AS category_name, c.icon AS category_icon,

            a.name AS payment_account_name,

            op.id AS payment_id, op.paid_amount_cents, op.paid_at, op.transaction_id

        FROM obligations o

        LEFT JOIN categories c ON o.category_id = c.id

        LEFT JOIN accounts a ON o.payment_account_id = a.id

        LEFT JOIN obligation_payments op ON o.id = op.obligation_id AND op.month_year = ?

        WHERE o.is_active = 1

        ORDER BY o.due_day ASC, o.name ASC;

        """, (month_year,))

        rows = cursor.fetchall()

        self._close_if_local(conn)

        result = []

        for r in rows:

            is_paid = r["payment_id"] is not None

            paid_cents = r["paid_amount_cents"] or 0

            amount_cents = r["amount_cents"]

            remaining_cents = 0 if is_paid else amount_cents

            result.append({

                "id": r["id"],

                "name": r["name"],

                "amount_cents": amount_cents,

                "amount_rub": cents_to_rubles(amount_cents),

                "due_day": r["due_day"],

                "note": r["note"],

                "category_id": r["category_id"],

                "category_name": r["category_name"] or "Без категории",

                "category_icon": r["category_icon"] or "tag",

                "payment_account_id": r["payment_account_id"],

                "payment_account_name": r["payment_account_name"] or "Не назначен",

                "is_paid_this_month": is_paid,

                "paid_amount_cents": paid_cents,

                "paid_amount_rub": cents_to_rubles(paid_cents),

                "remaining_cents": remaining_cents,

                "remaining_rub": cents_to_rubles(remaining_cents),

                "paid_at": r["paid_at"],

                "transaction_id": r["transaction_id"],

                "month_year": month_year

            })

        return result

    def mark_obligation_paid(

        self,

        obligation_id: str,

        month_year: Optional[str] = None,

        transaction_id: Optional[str] = None,

        paid_amount_cents: Optional[int] = None

    ) -> bool:

        """Mark an obligation as fulfilled for the specified month."""

        if not month_year:

            from datetime import datetime

            month_year = datetime.now().strftime("%Y-%m")

        conn = self._get_conn()

        cursor = conn.cursor()

        try:

            if paid_amount_cents is None:

                cursor.execute("SELECT amount_cents FROM obligations WHERE id = ?;", (obligation_id,))

                row = cursor.fetchone()

                if not row:

                    return False

                paid_amount_cents = row["amount_cents"]

            pay_id = generate_uuid()

            cursor.execute("""

            INSERT OR REPLACE INTO obligation_payments (id, obligation_id, month_year, transaction_id, paid_amount_cents, paid_at)

            VALUES (?, ?, ?, ?, ?, ?);

            """, (pay_id, obligation_id, month_year, transaction_id, paid_amount_cents, current_iso_time()))

            pay_payload = {

                "id": pay_id,

                "obligation_id": obligation_id,

                "month_year": month_year,

                "transaction_id": transaction_id,

                "paid_amount_cents": paid_amount_cents,

                "paid_at": current_iso_time()

            }

            self._get_sync_engine().record_change_event("OBLIGATION_PAYMENT", pay_id, "INSERT", pay_payload, cursor=cursor)

            conn.commit()

            self._save_if_encrypted()

            return True

        finally:

            self._close_if_local(conn)

    def set_initial_balance(

        self,

        account_id: str,

        balance_cents: int,

        date: Optional[str] = None

    ) -> str:

        """

        Record or update initial opening balance for an account using strict double-entry:

        - For ASSET accounts:

          Debit: account_id (balance_cents)

          Credit: 3010 Общий семейный капитал (balance_cents)

        - For LIABILITY accounts (credit card opening debt):

          Debit: 3010 Общий семейный капитал (balance_cents)

          Credit: account_id (balance_cents)

        """

        conn = self._get_conn()

        try:

            with conn:

                cursor = conn.cursor()

                cursor.execute("SELECT id, name, account_type, ownership_scope, initial_balance_cents FROM accounts WHERE id = ?;", (account_id,))

                acc = cursor.fetchone()

                if not acc:

                    raise ValueError(f"Счет {account_id} не найден.")

                # Locate Common Family Equity Account 3010

                cursor.execute("SELECT id FROM accounts WHERE code = '3010';")

                eq_row = cursor.fetchone()

                if not eq_row:

                    raise RuntimeError("Счет капитала '3010' не найден.")

                equity_id = eq_row["id"]

                # Check if an existing opening balance transaction exists for this account

                idem_key = f"init_bal_{account_id}"

                cursor.execute("SELECT id FROM transactions WHERE idempotency_key = ?;", (idem_key,))

                existing_tx = cursor.fetchone()

                # If existing tx found, remove previous postings to replace cleanly

                if existing_tx:

                    cursor.execute("DELETE FROM postings WHERE transaction_id = ?;", (existing_tx["id"],))

                    cursor.execute("DELETE FROM transactions WHERE id = ?;", (existing_tx["id"],))

                # Update initial_balance_cents column on account

                cursor.execute("UPDATE accounts SET initial_balance_cents = ? WHERE id = ?;", (balance_cents, account_id))

                if balance_cents > 0:

                    tx_id = generate_uuid()

                    tx_date = date or current_iso_time()[:10]

                    cursor.execute("""

                    INSERT INTO transactions (id, tx_date, tx_type, description, idempotency_key, is_voided, created_at)

                    VALUES (?, ?, 'ADJUSTMENT', ?, ?, 0, ?);

                    """, (tx_id, tx_date, f"Начальный остаток счета '{acc['name']}'", idem_key, current_iso_time()))

                    postings = []

                    if acc["account_type"] == "LIABILITY":

                        postings.append(Posting(id=generate_uuid(), transaction_id=tx_id, account_id=equity_id, amount_cents=balance_cents, posting_type="DEBIT", ownership_scope=acc["ownership_scope"]))

                        postings.append(Posting(id=generate_uuid(), transaction_id=tx_id, account_id=account_id, amount_cents=balance_cents, posting_type="CREDIT", ownership_scope=acc["ownership_scope"]))

                    else:

                        postings.append(Posting(id=generate_uuid(), transaction_id=tx_id, account_id=account_id, amount_cents=balance_cents, posting_type="DEBIT", ownership_scope=acc["ownership_scope"]))

                        postings.append(Posting(id=generate_uuid(), transaction_id=tx_id, account_id=equity_id, amount_cents=balance_cents, posting_type="CREDIT", ownership_scope=acc["ownership_scope"]))

                    for p in postings:

                        cursor.execute("""

                        INSERT INTO postings (id, transaction_id, account_id, amount_cents, posting_type, ownership_scope, purpose_allocation, created_at)

                        VALUES (?, ?, ?, ?, ?, ?, 'SAFE_TO_SPEND', ?);

                        """, (p.id, tx_id, p.account_id, p.amount_cents, p.posting_type, p.ownership_scope, current_iso_time()))

                    # Record CDC event

                    tx_payload = {

                        "id": tx_id,

                        "tx_date": tx_date,

                        "tx_type": "ADJUSTMENT",

                        "description": f"Начальный остаток счета '{acc['name']}'",

                        "postings": [

                            {"id": p.id, "account_id": p.account_id, "amount_cents": p.amount_cents, "posting_type": p.posting_type, "ownership_scope": p.ownership_scope}

                            for p in postings

                        ]

                    }

                    self._get_sync_engine().record_change_event("TRANSACTION", tx_id, "INSERT", tx_payload, cursor=cursor)

                conn.commit()

                self._save_if_encrypted()

                return account_id

        finally:

            self._close_if_local(conn)

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

            cents = int(b.get("balance_cents", 0))

            self.set_initial_balance(acc_id, cents)

            if "credit_limit_cents" in b and b["credit_limit_cents"] is not None:

                self.update_account(acc_id, name=None, credit_limit_cents=int(b["credit_limit_cents"]))

            applied_balances.append({"account_id": acc_id, "balance_cents": cents})

        applied_obligations = []

        if obligations:

            for o in obligations:

                obl = self.create_obligation(

                    name=o.get("name", "Обязательство"),

                    amount_cents=int(o.get("amount_cents", 0)),

                    due_day=int(o.get("due_day", 1)),

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

    def unmark_obligation_paid(self, obligation_id: str, month_year: Optional[str] = None) -> bool:

        """Remove paid status of an obligation for the specified month."""

        if not month_year:

            from datetime import datetime

            month_year = datetime.now().strftime("%Y-%m")

        conn = self._get_conn()

        cursor = conn.cursor()

        try:

            cursor.execute("DELETE FROM obligation_payments WHERE obligation_id = ? AND month_year = ?;", (obligation_id, month_year))

            if cursor.rowcount > 0:

                self._get_sync_engine().record_change_event("OBLIGATION_PAYMENT", obligation_id, "DELETE", {"obligation_id": obligation_id, "month_year": month_year}, cursor=cursor)

            conn.commit()

            self._save_if_encrypted()

            return cursor.rowcount > 0

        finally:

            self._close_if_local(conn)

    def calculate_unpaid_obligations_cents(self, month_year: Optional[str] = None) -> Tuple[int, int, int]:

        """

        Calculate (unpaid_cents, total_obligations_cents, paid_obligations_cents) for the given month.

        """

        obls = self.get_obligations(month_year)

        total_cents = sum(o["amount_cents"] for o in obls)

        paid_cents = sum(o["paid_amount_cents"] for o in obls if o["is_paid_this_month"])

        unpaid_cents = sum(o["remaining_cents"] for o in obls)

        return unpaid_cents, total_cents, paid_cents

    # ---------------------------------------------------------

    # Stage 7: Financial Analytics & Visual Spending Breakdown

    # ---------------------------------------------------------

    def get_spending_analytics(

        self,

        period: str = "current_month",

        start_date: Optional[str] = None,

        end_date: Optional[str] = None

    ) -> Dict[str, Any]:

        """

        Compute comprehensive spending analytics:

        - Total income, total expenses, net savings, savings rate %.

        - Breakdown by category (amount, percentage, icon, name, tx_count).

        - Breakdown by family member / ownership scope (amount, percentage, label).

        - Top 5 largest expenses in period.

        - Daily average expense and cash runway estimation.

        """

        from datetime import datetime, date, timedelta

        import calendar

        today = datetime.now().date()

        

        import re

        if start_date and end_date:

            s_date = start_date

            e_date = end_date

            label = f"{s_date} — {e_date}"

        elif re.match(r"^\d{4}-\d{2}$", period):

            year, month = map(int, period.split("-"))

            s_date = f"{year:04d}-{month:02d}-01"

            _, last_day = calendar.monthrange(year, month)

            e_date = f"{year:04d}-{month:02d}-{last_day:02d}"

            month_names_ru = ["", "Январь", "Февраль", "Март", "Апрель", "Май", "Июнь", "Июль", "Август", "Сентябрь", "Октябрь", "Ноябрь", "Декабрь"]

            label = f"{month_names_ru[month]} {year}"

        elif period == "prev_month":

            first_curr = today.replace(day=1)

            last_prev = first_curr - timedelta(days=1)

            first_prev = last_prev.replace(day=1)

            s_date = first_prev.isoformat()

            e_date = last_prev.isoformat()

            label = f"Предыдущий месяц ({first_prev.strftime('%m.%Y')})"

        elif period == "30d":

            s_date = (today - timedelta(days=30)).isoformat()

            e_date = today.isoformat()

            label = "Последние 30 дней"

        elif period == "90d":

            s_date = (today - timedelta(days=90)).isoformat()

            e_date = today.isoformat()

            label = "Последние 90 дней"

        elif period == "all":

            s_date = "1970-01-01"

            e_date = "2099-12-31"

            label = "За всё время"

        else:  # "current_month"

            s_date = today.replace(day=1).isoformat()

            _, last_day = calendar.monthrange(today.year, today.month)

            e_date = today.replace(day=last_day).isoformat()

            label = f"Текущий месяц ({today.strftime('%m.%Y')})"

        try:

            d_start = datetime.strptime(s_date, "%Y-%m-%d").date()

            d_end = datetime.strptime(e_date, "%Y-%m-%d").date()

            days_count = max(1, (min(today, d_end) - d_start).days + 1)

        except Exception:

            days_count = 30

        conn = self._get_conn()

        cursor = conn.cursor()

        # 1. Expenses: all debit postings to EXPENSE accounts in non-voided transactions

        cursor.execute("""

        SELECT 

            p.id AS posting_id,

            p.transaction_id,

            p.amount_cents,

            p.ownership_scope,

            p.category_id,

            t.tx_date,

            t.description,

            t.created_by_member_id,

            c.name AS category_name,

            c.icon AS category_icon,

            a.name AS account_name

        FROM postings p

        JOIN transactions t ON p.transaction_id = t.id

        JOIN accounts a ON p.account_id = a.id

        LEFT JOIN categories c ON p.category_id = c.id

        WHERE t.is_voided = 0

          AND a.account_type = 'EXPENSE'

          AND p.posting_type = 'DEBIT'

          AND t.tx_date BETWEEN ? AND ?

        ORDER BY p.amount_cents DESC;

        """, (s_date, e_date))

        expense_rows = cursor.fetchall()

        # 2. Incomes: all credit postings to INCOME accounts in non-voided transactions

        cursor.execute("""

        SELECT 

            p.id AS posting_id,

            p.transaction_id,

            p.amount_cents,

            p.ownership_scope,

            p.category_id,

            t.tx_date,

            t.description,

            t.created_by_member_id,

            c.name AS category_name,

            c.icon AS category_icon,

            a.name AS account_name

        FROM postings p

        JOIN transactions t ON p.transaction_id = t.id

        JOIN accounts a ON p.account_id = a.id

        LEFT JOIN categories c ON p.category_id = c.id

        WHERE t.is_voided = 0

          AND a.account_type = 'INCOME'

          AND p.posting_type = 'CREDIT'

          AND t.tx_date BETWEEN ? AND ?;

        """, (s_date, e_date))

        income_rows = cursor.fetchall()

        self._close_if_local(conn)

        total_expense_cents = sum(r["amount_cents"] for r in expense_rows)

        total_income_cents = sum(r["amount_cents"] for r in income_rows)

        net_savings_cents = total_income_cents - total_expense_cents

        if total_income_cents > 0:

            savings_rate_pct = round(((total_income_cents - total_expense_cents) / total_income_cents) * 100, 1)

        else:

            savings_rate_pct = 0.0

        daily_avg_expense_cents = round(total_expense_cents / days_count) if days_count > 0 else 0

        # Category breakdown

        cat_map = {}

        for r in expense_rows:

            cid = r["category_id"] or "uncategorized"

            cname = r["category_name"] or "Без категории"

            cicon = r["category_icon"] or "tag"

            if cid not in cat_map:

                cat_map[cid] = {

                    "id": cid,

                    "name": cname,

                    "icon": cicon,

                    "amount_cents": 0,

                    "tx_count": 0

                }

            cat_map[cid]["amount_cents"] += r["amount_cents"]

            cat_map[cid]["tx_count"] += 1

        categories_breakdown = list(cat_map.values())

        categories_breakdown.sort(key=lambda x: x["amount_cents"], reverse=True)

        for c in categories_breakdown:

            c["amount_rub"] = cents_to_rubles(c["amount_cents"])

            c["percent"] = round((c["amount_cents"] / total_expense_cents) * 100, 1) if total_expense_cents > 0 else 0.0

        # Family member attribution breakdown

        scope_map = {

            "COMMON": {"scope": "COMMON", "label": "Общие семейные", "icon": "👨‍👩‍👧‍👦", "amount_cents": 0, "tx_count": 0},

            "PERSONAL_HUSBAND": {"scope": "PERSONAL_HUSBAND", "label": "Муж", "icon": "👨", "amount_cents": 0, "tx_count": 0},

            "PERSONAL_WIFE": {"scope": "PERSONAL_WIFE", "label": "Жена", "icon": "👩", "amount_cents": 0, "tx_count": 0},

            "OTHER": {"scope": "OTHER", "label": "Прочие", "icon": "👤", "amount_cents": 0, "tx_count": 0}

        }

        for r in expense_rows:

            sc = r["ownership_scope"] or "COMMON"

            target_key = sc if sc in scope_map else "OTHER"

            scope_map[target_key]["amount_cents"] += r["amount_cents"]

            scope_map[target_key]["tx_count"] += 1

        members_breakdown = [v for v in scope_map.values() if v["amount_cents"] > 0 or v["scope"] in ("COMMON", "PERSONAL_HUSBAND", "PERSONAL_WIFE")]

        for m in members_breakdown:

            m["amount_rub"] = cents_to_rubles(m["amount_cents"])

            m["percent"] = round((m["amount_cents"] / total_expense_cents) * 100, 1) if total_expense_cents > 0 else 0.0

        # Top 5 largest expenses

        top_expenses = []

        for r in expense_rows[:5]:

            top_expenses.append({

                "transaction_id": r["transaction_id"],

                "date": r["tx_date"],

                "description": r["description"],

                "amount_cents": r["amount_cents"],

                "amount_rub": cents_to_rubles(r["amount_cents"]),

                "category_name": r["category_name"] or "Без категории",

                "category_icon": r["category_icon"] or "tag"

            })

        # Calculate Cash Runway (days until liquid funds run out at current daily burn)

        overview = self.get_financial_overview()

        liquid_cents = overview["common_liquid_assets_cents"]

        if daily_avg_expense_cents > 0:

            cash_runway_days = round(liquid_cents / daily_avg_expense_cents)

        else:

            cash_runway_days = None

        return {

            "period": period,

            "period_label": label,

            "start_date": s_date,

            "end_date": e_date,

            "days_count": days_count,

            "total_income_cents": total_income_cents,

            "total_income_rub": cents_to_rubles(total_income_cents),

            "total_expense_cents": total_expense_cents,

            "total_expense_rub": cents_to_rubles(total_expense_cents),

            "net_savings_cents": net_savings_cents,

            "net_savings_rub": cents_to_rubles(net_savings_cents),

            "savings_rate_percent": savings_rate_pct,

            "daily_avg_expense_cents": daily_avg_expense_cents,

            "daily_avg_expense_rub": cents_to_rubles(daily_avg_expense_cents),

            "cash_runway_days": cash_runway_days,

            "categories": categories_breakdown,

            "members": members_breakdown,

            "top_expenses": top_expenses

        }

    # ---------------------------------------------------------

    # Stage 7: 30/60/90-Day Cash Flow Forecasting Engine

    # ---------------------------------------------------------

    def get_cash_flow_forecast(

        self,

        days: int = 30,

        include_burn_rate: bool = True,

        custom_daily_burn_cents: Optional[int] = None,

        safety_buffer_cents: int = 0

    ) -> Dict[str, Any]:

        """

        Simulate 30, 60, or 90-day daily cash flow trajectory:

        - Day 0 starts with Net Liquid Position (Liquid Cards & Cash MINUS Credit Card Debt).

        - Long-term reserves (SAVINGS/DEPOSIT) are isolated as a Safety Baseline.

        - Every calendar day evaluates scheduled obligations (due_day).

        - Obligations already paid in current month are NOT double-deducted this month.

        - Daily discretionary burn rate is computed from variable spending (excluding fixed obligations & outliers).

        - Hard Cash Gap (Balance < 0) and Soft Gap (Balance < Safety Buffer) pinpoint exact date and triggering event.

        """

        from datetime import datetime, date, timedelta

        import calendar

        days = min(max(days, 7), 90)

        today = datetime.now().date()

        overview = self.get_financial_overview()

        starting_liquid_cents = overview["common_liquid_assets_cents"]

        credit_debt_cents = overview["credit_cards"]["total_debt_cents"]

        emergency_reserves_cents = overview["emergency_reserves_cents"]

        

        # Net Liquid Position on Day 0

        effective_start_cents = starting_liquid_cents - credit_debt_cents

        # 1. Calculate Daily Discretionary Burn Rate from historical non-obligation expenses

        lookback_start = (today - timedelta(days=30)).isoformat()

        lookback_end = today.isoformat()

        

        conn = self._get_conn()

        cursor = conn.cursor()

        

        # Find all obligations category IDs or names to exclude from variable burn rate

        cursor.execute("SELECT category_id, amount_cents FROM obligations WHERE is_active = 1;")

        obl_meta = cursor.fetchall()

        obl_cat_ids = {r["category_id"] for r in obl_meta if r["category_id"]}

        

        # Query historical discretionary expenses in the last 30 days

        cursor.execute("""

        SELECT p.amount_cents, p.category_id, t.tx_date

        FROM postings p

        JOIN transactions t ON p.transaction_id = t.id

        JOIN accounts a ON p.account_id = a.id

        WHERE t.is_voided = 0

          AND a.account_type = 'EXPENSE'

          AND p.posting_type = 'DEBIT'

          AND t.tx_date BETWEEN ? AND ?

        """, (lookback_start, lookback_end))

        hist_rows = cursor.fetchall()

        

        # Count active transaction days in history to handle cold start

        cursor.execute("""

        SELECT COUNT(DISTINCT t.tx_date) AS active_days

        FROM transactions t

        WHERE t.is_voided = 0 AND t.tx_date BETWEEN ? AND ?

        """, (lookback_start, lookback_end))

        active_days_row = cursor.fetchone()

        active_days_count = active_days_row["active_days"] if active_days_row else 0

        

        self._close_if_local(conn)

        # Filter out fixed obligations categories and extreme outliers (> 100 000 RUB per item)

        discretionary_sum_cents = 0

        for hr in hist_rows:

            if hr["category_id"] not in obl_cat_ids and hr["amount_cents"] < 10000000:

                discretionary_sum_cents += hr["amount_cents"]

        # If cold start (< 3 active days), do not artificially burn without real history

        if custom_daily_burn_cents is not None:

            daily_burn_cents = max(0, custom_daily_burn_cents)

            burn_rate_source = "custom"

        elif active_days_count < 3 or not include_burn_rate:

            daily_burn_cents = 0

            burn_rate_source = "cold_start_or_disabled" if active_days_count < 3 else "disabled"

        else:

            # Average daily burn over 30 days

            daily_burn_cents = round(discretionary_sum_cents / 30)

            burn_rate_source = "historical_30d"

        # 2. Retrieve all active obligations and payment status

        all_obligations = self.get_obligations()

        # 3. Daily Simulation

        current_balance_cents = effective_start_cents

        timeline_points = []

        

        has_deficit = False

        first_deficit_date = None

        first_deficit_cents = 0

        first_deficit_trigger = None

        

        min_projected_balance_cents = current_balance_cents

        # Map paid obligations for current month

        curr_month_str = today.strftime("%Y-%m")

        curr_month_paid_ids = {o["id"] for o in all_obligations if o.get("is_paid_this_month")}

        # Milestone events for charting

        milestones = []

        for step in range(1, days + 1):

            sim_date = today + timedelta(days=step)

            sim_month_str = sim_date.strftime("%Y-%m")

            sim_day = sim_date.day

            

            day_events = []

            day_obligations_cents = 0

            

            # Check obligations due on sim_day

            for obl in all_obligations:

                _, days_in_sim_month = calendar.monthrange(sim_date.year, sim_date.month)

                effective_due_day = min(obl["due_day"], days_in_sim_month)

                

                if sim_day == effective_due_day:

                    # In current calendar month: if already paid, skip

                    if sim_month_str == curr_month_str and obl["id"] in curr_month_paid_ids:

                        continue

                    

                    obl_amt = obl["amount_cents"]

                    day_obligations_cents += obl_amt

                    day_events.append({

                        "type": "OBLIGATION",

                        "name": obl["name"],

                        "amount_cents": obl_amt,

                        "amount_rub": cents_to_rubles(obl_amt)

                    })

                    milestones.append({

                        "date": sim_date.isoformat(),

                        "day": step,

                        "label": f"{obl['name']} ({cents_to_rubles(obl_amt)} ₽)",

                        "amount_cents": obl_amt

                    })

            # Daily burn

            burn_today_cents = daily_burn_cents if include_burn_rate else 0

            if burn_today_cents > 0:

                day_events.append({

                    "type": "BURN_RATE",

                    "name": "Повседневные траты",

                    "amount_cents": burn_today_cents,

                    "amount_rub": cents_to_rubles(burn_today_cents)

                })

            net_change_cents = - (day_obligations_cents + burn_today_cents)

            current_balance_cents += net_change_cents

            if current_balance_cents < min_projected_balance_cents:

                min_projected_balance_cents = current_balance_cents

            is_point_deficit = (current_balance_cents < 0)

            if is_point_deficit and not has_deficit:

                has_deficit = True

                first_deficit_date = sim_date.isoformat()

                first_deficit_cents = abs(current_balance_cents)

                if day_events:

                    first_deficit_trigger = day_events[0]["name"]

                else:

                    first_deficit_trigger = "Накопленный дефицит"

            timeline_points.append({

                "day_index": step,

                "date": sim_date.isoformat(),

                "day_formatted": sim_date.strftime("%d.%m"),

                "day_of_week": sim_date.strftime("%a"),

                "balance_cents": current_balance_cents,

                "balance_rub": cents_to_rubles(current_balance_cents),

                "is_deficit": is_point_deficit,

                "net_change_cents": net_change_cents,

                "net_change_rub": cents_to_rubles(net_change_cents),

                "events": day_events

            })

        # Calculate autonomy runway

        total_daily_rate_cents = daily_burn_cents

        if all_obligations:

            monthly_obls = sum(o["amount_cents"] for o in all_obligations)

            total_daily_rate_cents += round(monthly_obls / 30)

        if total_daily_rate_cents > 0:

            runway_days = max(0, round(effective_start_cents / total_daily_rate_cents))

        else:

            runway_days = None

        return {

            "forecast_days": days,

            "start_date": today.isoformat(),

            "end_date": (today + timedelta(days=days)).isoformat(),

            "starting_liquid_cents": starting_liquid_cents,

            "starting_liquid_rub": cents_to_rubles(starting_liquid_cents),

            "credit_debt_cents": credit_debt_cents,

            "credit_debt_rub": cents_to_rubles(credit_debt_cents),

            "effective_start_cents": effective_start_cents,

            "effective_start_rub": cents_to_rubles(effective_start_cents),

            "emergency_reserves_cents": emergency_reserves_cents,

            "emergency_reserves_rub": cents_to_rubles(emergency_reserves_cents),

            "daily_burn_cents": daily_burn_cents,

            "daily_burn_rub": cents_to_rubles(daily_burn_cents),

            "burn_rate_source": burn_rate_source,

            "has_deficit": has_deficit,

            "first_deficit_date": first_deficit_date,

            "first_deficit_cents": first_deficit_cents,

            "first_deficit_rub": cents_to_rubles(first_deficit_cents),

            "first_deficit_trigger": first_deficit_trigger,

            "min_projected_balance_cents": min_projected_balance_cents,

            "min_projected_balance_rub": cents_to_rubles(min_projected_balance_cents),

            "cash_runway_days": runway_days,

            "milestones": milestones,

            "timeline": timeline_points

        }

    # ---------------------------------------------------------

    # 8. Financial Goals (Stage 9 Savings Targets)

    # ---------------------------------------------------------

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

        if target_amount_cents <= 0:

            raise ValueError("Целевая сумма должна быть строго больше нуля.")

        if initial_saved_cents < 0:

            raise ValueError("Начальные накопления не могут быть отрицательными.")

        goal_id = generate_uuid()

        conn = self._get_conn()

        cursor = conn.cursor()

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

            conn.commit()

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

                updates.append("name = ?")

                params.append(name.strip())

            if target_amount_cents is not None:

                if target_amount_cents <= 0:

                    raise ValueError("Целевая сумма должна быть строго больше нуля.")

                updates.append("target_amount_cents = ?")

                params.append(target_amount_cents)

            if target_date is not None:

                updates.append("target_date = ?")

                params.append(target_date)

            if account_id is not None:

                updates.append("account_id = ?")

                params.append(account_id or None)

            if category_id is not None:

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

                    self._get_sync_engine().record_change_event("GOAL", goal_id, "UPDATE", dict(row), cursor=cursor)

                conn.commit()

                self._save_if_encrypted()

                return True

            return False

        finally:

            self._close_if_local(conn)

    def archive_goal(self, goal_id: str) -> bool:

        conn = self._get_conn()

        cursor = conn.cursor()

        try:

            cursor.execute("UPDATE goals SET is_active = 0 WHERE id = ?;", (goal_id,))

            if cursor.rowcount > 0:

                self._get_sync_engine().record_change_event("GOAL", goal_id, "UPDATE", {"id": goal_id, "is_active": 0}, cursor=cursor)

                conn.commit()

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

                            months_left = max(1, round(days_left / 30.4))

                            monthly_cents = round(rem_cents / months_left)

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

    def contribute_to_goal(

        self,

        goal_id: str,

        amount_cents: int,

        source_account_id: Optional[str] = None,

        note: Optional[str] = None,

        member_id: Optional[str] = None,

        idempotency_key: Optional[str] = None

    ) -> Dict[str, Any]:

        if amount_cents <= 0:

            raise ValueError("Сумма пополнения цели должна быть строго больше нуля.")

        conn = self._get_conn()

        cursor = conn.cursor()

        try:

            cursor.execute("SELECT * FROM goals WHERE id = ? AND is_active = 1;", (goal_id,))

            goal_row = cursor.fetchone()

            if not goal_row:

                raise ValueError("Цель не найдена или неактивна.")

            tx_id = None

            if source_account_id:

                dest_acc_id = goal_row["account_id"]

                if not dest_acc_id:

                    cursor.execute("SELECT id FROM accounts WHERE code = '1030' AND is_active = 1;")

                    sav_row = cursor.fetchone()

                    if sav_row:

                        dest_acc_id = sav_row["id"]

                if dest_acc_id and dest_acc_id != source_account_id:

                    tx_id = self.record_transfer(

                        from_account_id=source_account_id,

                        to_account_id=dest_acc_id,

                        amount_cents=amount_cents,

                        description=f"Пополнение цели: {goal_row['name']}",

                        created_by_member_id=member_id,

                        idempotency_key=idempotency_key

                    )

            new_current = goal_row["current_amount_cents"] + amount_cents

            is_comp = 1 if new_current >= goal_row["target_amount_cents"] else 0

            cursor.execute("""

            UPDATE goals SET current_amount_cents = ?, is_completed = ? WHERE id = ?;

            """, (new_current, is_comp, goal_id))

            contrib_id = generate_uuid()

            cursor.execute("""

            INSERT INTO goal_contributions (id, goal_id, amount_cents, transaction_id, source_account_id, note, created_at)

            VALUES (?, ?, ?, ?, ?, ?, ?);

            """, (contrib_id, goal_id, amount_cents, tx_id, source_account_id, note, current_iso_time()))

            self._get_sync_engine().record_change_event("GOAL", goal_id, "UPDATE", {

                "id": goal_id,

                "current_amount_cents": new_current,

                "is_completed": is_comp

            }, cursor=cursor)

            self._get_sync_engine().record_change_event("GOAL_CONTRIBUTION", contrib_id, "INSERT", {

                "id": contrib_id,

                "goal_id": goal_id,

                "amount_cents": amount_cents,

                "transaction_id": tx_id,

                "source_account_id": source_account_id,

                "note": note,

                "created_at": current_iso_time()

            }, cursor=cursor)

            conn.commit()

            self._save_if_encrypted()

            return {

                "status": "success",

                "goal_id": goal_id,

                "new_current_cents": new_current,

                "new_current_rub": cents_to_rubles(new_current),

                "is_completed": bool(is_comp),

                "transaction_id": tx_id

            }

        finally:

            self._close_if_local(conn)

    # ---------------------------------------------------------

    # 9. Debts & Debt Repayments (Stage 9 Liabilities)

    # ---------------------------------------------------------

    def get_debts_summary(self) -> Dict[str, Any]:

        """

        Get structured overview of all liabilities, debts, credit cards and loans.

        """

        conn = self._get_conn()

        cursor = conn.cursor()

        try:

            cursor.execute("""

            SELECT 

                a.id, a.code, a.name, a.subtype, a.credit_limit_cents, a.ownership_scope,

                COALESCE(SUM(CASE WHEN p.posting_type = 'CREDIT' THEN p.amount_cents ELSE 0 END), 0) -

                COALESCE(SUM(CASE WHEN p.posting_type = 'DEBIT' THEN p.amount_cents ELSE 0 END), 0) as balance_cents

            FROM accounts a

            LEFT JOIN postings p ON a.id = p.account_id

            LEFT JOIN transactions t ON p.transaction_id = t.id AND t.is_voided = 0

            WHERE a.account_type = 'LIABILITY' AND a.is_active = 1

            GROUP BY a.id

            ORDER BY a.code;

            """)

            rows = cursor.fetchall()

            # Also check recurring obligations linked to liabilities

            cursor.execute("""

            SELECT o.id, o.name, o.amount_cents, o.due_day, o.payment_account_id,

                   op.paid_amount_cents, op.paid_at

            FROM obligations o

            LEFT JOIN obligation_payments op ON o.id = op.obligation_id AND op.month_year = ?

            WHERE o.is_active = 1;

            """, (current_iso_time()[:7],))

            ob_rows = cursor.fetchall()

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

                        "is_paid": ob["paid_amount_cents"] is not None

                    }

            debts = []

            total_debt_cents = 0

            credit_cards_debt_cents = 0

            loans_debt_cents = 0

            for r in rows:

                bal = max(0, r["balance_cents"])

                limit = r["credit_limit_cents"] or 0

                subtype = r["subtype"]

                if subtype == "CREDIT_CARD":

                    credit_cards_debt_cents += bal

                    avail_cents = max(0, limit - bal)

                else:

                    loans_debt_cents += bal

                    avail_cents = 0

                total_debt_cents += bal

                debts.append({

                    "id": r["id"],

                    "code": r["code"],

                    "name": r["name"],

                    "subtype": subtype,

                    "debt_cents": bal,

                    "debt_rub": cents_to_rubles(bal),

                    "credit_limit_cents": limit,

                    "credit_limit_rub": cents_to_rubles(limit),

                    "available_cents": avail_cents,

                    "available_rub": cents_to_rubles(avail_cents),

                    "linked_obligation": ob_by_acc.get(r["id"])

                })

            return {

                "debts": debts,

                "total_debt_cents": total_debt_cents,

                "total_debt_rub": cents_to_rubles(total_debt_cents),

                "credit_cards_debt_cents": credit_cards_debt_cents,

                "credit_cards_debt_rub": cents_to_rubles(credit_cards_debt_cents),

                "loans_debt_cents": loans_debt_cents,

                "loans_debt_rub": cents_to_rubles(loans_debt_cents)

            }

        finally:

            self._close_if_local(conn)

    def record_debt_repayment(

        self,

        source_account_id: str,

        liability_account_id: str,

        amount_cents: int,

        description: Optional[str] = None,

        obligation_id: Optional[str] = None,

        member_id: Optional[str] = None,

        idempotency_key: Optional[str] = None

    ) -> str:

        """

        Record strict double-entry debt repayment:

        DEBIT: Liability account (reduces debt)

        CREDIT: Source asset account (reduces cash/card)

        Type: CREDIT_PAYMENT if subtype is CREDIT_CARD, else LOAN_REPAYMENT

        """

        if amount_cents <= 0:

            raise ValueError("Сумма погашения задолженности должна быть строго больше нуля.")

        source_acc = self.get_account_by_id(source_account_id)

        if not source_acc or source_acc.account_type != "ASSET":

            raise ValueError(f"Счет списания {source_account_id} не найден или не является счетом активов.")

        liability_acc = self.get_account_by_id(liability_account_id)

        if not liability_acc or liability_acc.account_type != "LIABILITY":

            raise ValueError(f"Счет задолженности {liability_account_id} не найден или не является счетом обязательств.")

        tx_type = "CREDIT_PAYMENT" if liability_acc.subtype == "CREDIT_CARD" else "LOAN_REPAYMENT"

        desc = description.strip() if description and description.strip() else f"Погашение: {liability_acc.name}"

        tx_id = generate_uuid()

        tx_date = current_iso_time()[:10]

        postings = [

            # DEBIT Liability (reduces liability balance)

            Posting(

                id=generate_uuid(),

                transaction_id=tx_id,

                account_id=liability_acc.id,

                amount_cents=amount_cents,

                posting_type="DEBIT",

                ownership_scope=liability_acc.ownership_scope,

                purpose_allocation="SAFE_TO_SPEND",

                note=f"Погашение долга по '{liability_acc.name}'"

            ),

            # CREDIT Asset (cash/card reduction)

            Posting(

                id=generate_uuid(),

                transaction_id=tx_id,

                account_id=source_acc.id,

                amount_cents=amount_cents,

                posting_type="CREDIT",

                ownership_scope=source_acc.ownership_scope,

                purpose_allocation="SAFE_TO_SPEND",

                note=f"Оплата задолженности: '{liability_acc.name}'"

            )

        ]

        tx = Transaction(

            id=tx_id,

            tx_date=tx_date,

            tx_type=tx_type,

            description=desc,

            created_by_member_id=member_id,

            postings=postings

        )

        saved_id = self.record_transaction(tx, idempotency_key=idempotency_key)

        # If linked obligation specified, mark it paid

        if obligation_id:

            self.mark_obligation_paid(

                obligation_id=obligation_id,

                transaction_id=saved_id,

                paid_amount_cents=amount_cents

            )

        return saved_id

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

            self._get_sync_engine().record_change_event("ENVELOPE", env_id, "INSERT", payload, cursor=cursor)

            if initial_amount_cents > 0:

                op_id = generate_uuid()

                cursor.execute("""

                INSERT INTO envelope_operations (id, envelope_id, operation_type, amount_cents, note)

                VALUES (?, ?, 'DEPOSIT', ?, 'Начальный остаток копилки');

                """, (op_id, env_id, initial_amount_cents))

            conn.commit()

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

    def update_envelope(

        self,

        envelope_id: str,

        name: Optional[str] = None,

        target_amount_cents: Optional[int] = None,

        icon: Optional[str] = None,

        color: Optional[str] = None,

        linked_account_id: Optional[str] = None,

        category_id: Optional[str] = None,

        note: Optional[str] = None

    ) -> bool:

        """Update envelope parameters."""

        conn = self._get_conn()

        cursor = conn.cursor()

        try:

            updates = []

            params = []

            if name is not None:

                updates.append("name = ?")

                params.append(name.strip())

            if target_amount_cents is not None:

                updates.append("target_amount_cents = ?")

                params.append(target_amount_cents)

            if icon is not None:

                updates.append("icon = ?")

                params.append(icon)

            if color is not None:

                updates.append("color = ?")

                params.append(color)

            if linked_account_id is not None:

                updates.append("linked_account_id = ?")

                params.append(linked_account_id or None)

            if category_id is not None:

                updates.append("category_id = ?")

                params.append(category_id or None)

            if note is not None:

                updates.append("note = ?")

                params.append(note or None)

            if not updates:

                return True

            params.append(envelope_id)

            cursor.execute(f"UPDATE envelopes SET {', '.join(updates)} WHERE id = ? AND is_active = 1;", tuple(params))

            if cursor.rowcount > 0:

                cursor.execute("SELECT * FROM envelopes WHERE id = ?;", (envelope_id,))

                row = cursor.fetchone()

                if row:

                    self._get_sync_engine().record_change_event("ENVELOPE", envelope_id, "UPDATE", dict(row), cursor=cursor)

            conn.commit()

            self._save_if_encrypted()

            return cursor.rowcount > 0

        finally:

            self._close_if_local(conn)

    def archive_envelope(self, envelope_id: str) -> bool:

        """Archive an envelope (soft-delete)."""

        conn = self._get_conn()

        cursor = conn.cursor()

        try:

            cursor.execute("UPDATE envelopes SET is_active = 0 WHERE id = ?;", (envelope_id,))

            if cursor.rowcount > 0:

                self._get_sync_engine().record_change_event("ENVELOPE", envelope_id, "UPDATE", {"id": envelope_id, "is_active": 0}, cursor=cursor)

            conn.commit()

            self._save_if_encrypted()

            return cursor.rowcount > 0

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

            "total_saved_cents": total_cents,

            "total_saved_rub": cents_to_rubles(total_cents),

            "total_target_cents": target_cents,

            "total_target_rub": cents_to_rubles(target_cents)

        }

    def deposit_to_envelope(

        self,

        envelope_id: str,

        amount_cents: int,

        source_account_id: Optional[str] = None,

        note: Optional[str] = None,

        member_id: Optional[str] = None

    ) -> Dict[str, Any]:

        """Put money into a savings envelope (положить в копилку)."""

        if amount_cents <= 0:

            raise ValueError("Сумма пополнения конверта должна быть больше нуля.")

        conn = self._get_conn()

        cursor = conn.cursor()

        try:

            cursor.execute("SELECT * FROM envelopes WHERE id = ? AND is_active = 1;", (envelope_id,))

            env = cursor.fetchone()

            if not env:

                raise ValueError("Конверт-копилка не найден.")

            new_balance = env["current_amount_cents"] + amount_cents

            cursor.execute("UPDATE envelopes SET current_amount_cents = ? WHERE id = ?;", (new_balance, envelope_id))

            op_id = generate_uuid()

            cursor.execute("""

            INSERT INTO envelope_operations (id, envelope_id, operation_type, amount_cents, source_account_id, note, member_id)

            VALUES (?, ?, 'DEPOSIT', ?, ?, ?, ?);

            """, (op_id, envelope_id, amount_cents, source_account_id, note, member_id))

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

                    created_by_member_id=member_id

                )

            conn.commit()

            self._save_if_encrypted()

            return {

                "status": "success",

                "envelope_id": envelope_id,

                "amount_rub": cents_to_rubles(amount_cents),

                "new_balance_rub": cents_to_rubles(new_balance),

                "transaction_id": tx_id

            }

        finally:

            self._close_if_local(conn)

    def withdraw_from_envelope(

        self,

        envelope_id: str,

        amount_cents: int,

        destination_account_id: Optional[str] = None,

        note: Optional[str] = None,

        member_id: Optional[str] = None

    ) -> Dict[str, Any]:

        """Take money out of a savings envelope (взять из копилки / потратить)."""

        if amount_cents <= 0:

            raise ValueError("Сумма списания из конверта должна быть больше нуля.")

        conn = self._get_conn()

        cursor = conn.cursor()

        try:

            cursor.execute("SELECT * FROM envelopes WHERE id = ? AND is_active = 1;", (envelope_id,))

            env = cursor.fetchone()

            if not env:

                raise ValueError("Конверт-копилка не найден.")

            if env["current_amount_cents"] < amount_cents:

                raise ValueError(f"Недостаточно средств в конверте '{env['name']}'. Доступно: {cents_to_rubles(env['current_amount_cents'])} ₽.")

            new_balance = env["current_amount_cents"] - amount_cents

            cursor.execute("UPDATE envelopes SET current_amount_cents = ? WHERE id = ?;", (new_balance, envelope_id))

            op_id = generate_uuid()

            cursor.execute("""

            INSERT INTO envelope_operations (id, envelope_id, operation_type, amount_cents, destination_account_id, note, member_id)

            VALUES (?, ?, 'WITHDRAW', ?, ?, ?, ?);

            """, (op_id, envelope_id, amount_cents, destination_account_id, note, member_id))

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

                    created_by_member_id=member_id

                )

            conn.commit()

            self._save_if_encrypted()

            return {

                "status": "success",

                "envelope_id": envelope_id,

                "amount_rub": cents_to_rubles(amount_cents),

                "new_balance_rub": cents_to_rubles(new_balance),

                "transaction_id": tx_id

            }

        finally:

            self._close_if_local(conn)

    def transfer_between_envelopes(

        self,

        from_envelope_id: str,

        to_envelope_id: str,

        amount_cents: int,

        note: Optional[str] = None,

        member_id: Optional[str] = None

    ) -> Dict[str, Any]:

        """Transfer money from one envelope to another (переложить между конвертами)."""

        if amount_cents <= 0:

            raise ValueError("Сумма перевода должна быть больше нуля.")

        if from_envelope_id == to_envelope_id:

            raise ValueError("Нельзя перевести средства в тот же самый конверт.")

        conn = self._get_conn()

        cursor = conn.cursor()

        try:

            cursor.execute("SELECT * FROM envelopes WHERE id = ? AND is_active = 1;", (from_envelope_id,))

            env_from = cursor.fetchone()

            cursor.execute("SELECT * FROM envelopes WHERE id = ? AND is_active = 1;", (to_envelope_id,))

            env_to = cursor.fetchone()

            if not env_from or not env_to:

                raise ValueError("Один из указанных конвертов не найден.")

            if env_from["current_amount_cents"] < amount_cents:

                raise ValueError(f"Недостаточно средств в конверте '{env_from['name']}'. Доступно: {cents_to_rubles(env_from['current_amount_cents'])} ₽.")

            new_from_balance = env_from["current_amount_cents"] - amount_cents

            new_to_balance = env_to["current_amount_cents"] + amount_cents

            cursor.execute("UPDATE envelopes SET current_amount_cents = ? WHERE id = ?;", (new_from_balance, from_envelope_id))

            cursor.execute("UPDATE envelopes SET current_amount_cents = ? WHERE id = ?;", (new_to_balance, to_envelope_id))

            op_id = generate_uuid()

            cursor.execute("""

            INSERT INTO envelope_operations (id, envelope_id, operation_type, amount_cents, target_envelope_id, note, member_id)

            VALUES (?, ?, 'TRANSFER', ?, ?, ?, ?);

            """, (op_id, from_envelope_id, amount_cents, to_envelope_id, note, member_id))

            # Record CDCs

            cursor.execute("SELECT * FROM envelopes WHERE id = ?;", (from_envelope_id,))

            self._get_sync_engine().record_change_event("ENVELOPE", from_envelope_id, "UPDATE", dict(cursor.fetchone()), cursor=cursor)

            cursor.execute("SELECT * FROM envelopes WHERE id = ?;", (to_envelope_id,))

            self._get_sync_engine().record_change_event("ENVELOPE", to_envelope_id, "UPDATE", dict(cursor.fetchone()), cursor=cursor)

            conn.commit()

            self._save_if_encrypted()

            return {

                "status": "success",

                "from_envelope_id": from_envelope_id,

                "to_envelope_id": to_envelope_id,

                "amount_rub": cents_to_rubles(amount_cents),

                "from_new_balance_rub": cents_to_rubles(new_from_balance),

                "to_new_balance_rub": cents_to_rubles(new_to_balance)

            }

        finally:

            self._close_if_local(conn)

