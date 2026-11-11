"""
Family Finances OS - Universal Bank Statement & CSV/XLSX Importer
Enables families to import statements from any major bank (Sberbank, T-Bank, Alfa-Bank, VTB, Tinkoff)
or custom CSV/Excel sheets with automated category guessing, double-entry balancing, and deduplication.
"""
import csv
import hashlib
import io
import json
import re
from collections import defaultdict
from datetime import date
from typing import List, Dict, Any, Optional, Tuple

from family_finances_os.models import (
    Transaction,
    Posting,
    rubles_to_cents,
    cents_to_rubles,
    generate_uuid,
    current_iso_time
)
from family_finances_os.models import require_cents
from family_finances_os.ledger import LedgerEngine


CATEGORY_KEYWORDS = {
    "Продукты": ["супермаркет", "магнит", "пятерочка", "перекресток", "вкусвилл", "лента", "ашан", "дикси", "spar", "продукты", "food", "grocery"],
    "Рестораны и кафе": ["ресторан", "кафе", "кофе", "додо", "dodo", "бургер", "вкусно и точка", "шоколадница", "столовая", "coffee"],
    "Транспорт и авто": ["такси", "яндекс go", "yandex taxi", "uber", "бензин", "азс", "лукойл", "газпром", "роснефть", "парковка", "метро", "тройка", "каршеринг"],
    "Здоровье и медицина": ["аптека", "горздрав", "ригла", "вита", "доктор", "клиника", "стоматолог", "анализы", "гемотест", "инвитро", "медицин"],
    "Одежда и обувь": ["одежда", "обувь", "zara", "befree", "gloria", "спортмастер", "lamoda", "ламода"],
    "Маркетплейсы": ["wildberries", "вайлдберриз", "ozon", "озон", "яндекс маркет", "алиэкспресс", "aliexpress"],
    "Жилье и коммуналка": ["жкх", "мосэнерго", "квартплата", "водоканал", "капремонт", "газ", "домофон", "аренда"],
    "Связь и интернет": ["мтс", "мегафон", "билайн", "tele2", "т-мобайл", "ростелеком", "интернет", "связь"],
    "Дети и образование": ["детский сад", "школа", "кружок", "секция", "репетитор", "детский мир", "курсы"],
    "Развлечения и подписки": ["кино", "театр", "музей", "яндекс плюс", "кинопоиск", "иви", "подписка", "games", "steam"],
    "Зарплата и аванс": ["зарплата", "аванс", "заработная плата", "оклад", "премия", "выплата зп", "доход от работодателя"]
}


def clean_amount_str(val: str) -> Tuple[int, str]:
    """
    Parse a numeric string from bank CSV into integer cents and direction ('INCOME' or 'EXPENSE').
    Handles '1 234,50', '-500.00', '1234.50 ₽', '(500,00)'.
    """
    val = val.strip().replace("₽", "").replace("RUB", "").replace("руб", "").replace(" ", "").replace("\xa0", "")
    is_negative = False
    if val.startswith("(") and val.endswith(")"):
        is_negative = True
        val = val[1:-1]
    elif val.startswith("-"):
        is_negative = True
        val = val[1:]
    elif val.startswith("+"):
        val = val[1:]

    val = val.replace(",", ".")
    try:
        cents = abs(rubles_to_cents(val))
        direction = "EXPENSE" if is_negative else "INCOME"
        return cents, direction
    except Exception:
        return 0, "EXPENSE"


def guess_category(description: str, categories: List[Dict[str, Any]], direction: str) -> Optional[Dict[str, Any]]:
    """Auto-detect most suitable category by keyword heuristics."""
    desc_lower = description.lower()
    for cat_name, keywords in CATEGORY_KEYWORDS.items():
        for kw in keywords:
            if kw in desc_lower:
                match = next((c for c in categories if cat_name.lower() in c["name"].lower() or any(k in c["name"].lower() for k in keywords[:3])), None)
                if match:
                    return match

    # Fallback to general category of matching type
    target_type = "INCOME" if direction == "INCOME" else "EXPENSE"
    fallback = next((c for c in categories if c.get("type") == target_type or c.get("category_type") == target_type), None)
    return fallback


class StatementImporter:
    """
    Universal Parser and Processor for Bank Statements (CSV/TSV/JSON).
    """
    def __init__(self, ledger: Optional[LedgerEngine] = None):
        self.ledger = ledger or LedgerEngine()

    def parse_csv(self, raw_content: str, delimiter: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Parse raw CSV string into a preview list of normalized candidate transactions.
        """
        if not delimiter:
            first_line = raw_content.splitlines()[0] if raw_content else ""
            delimiter = ";" if ";" in first_line else ","

        reader = csv.reader(io.StringIO(raw_content), delimiter=delimiter)
        rows = list(reader)
        if not rows:
            return []

        header = [col.strip().lower() for col in rows[0]]
        date_idx = -1
        desc_idx = -1
        amount_idx = -1
        bank_id_idx = -1

        for i, col in enumerate(header):
            if any(k in col for k in ["transaction id", "transaction_id", "id операции", "идентификатор", "номер операции", "reference"]):
                bank_id_idx = i
            elif any(k in col for k in ["дата", "date", "время", "операция"]):
                if date_idx == -1: date_idx = i
            elif any(k in col for k in ["описание", "назначение", "детали", "description", "контрагент", "получатель", "статья"]):
                if desc_idx == -1: desc_idx = i
            elif any(k in col for k in ["сумма", "amount", "списание", "расход", "поступление"]):
                if amount_idx == -1: amount_idx = i

        # Fallback to column positions if header detection didn't match
        if date_idx == -1: date_idx = 0
        if desc_idx == -1: desc_idx = 1 if len(header) > 1 else 0
        if amount_idx == -1: amount_idx = 2 if len(header) > 2 else -1

        categories = self.ledger.get_flat_categories()
        parsed_items = []
        occurrences = defaultdict(int)

        for row_idx, row in enumerate(rows[1:], start=2):
            if not row or len(row) <= max(date_idx, amount_idx):
                continue
            raw_date = row[date_idx].strip()
            raw_desc = row[desc_idx].strip() if desc_idx < len(row) else "Банковская операция"
            raw_amount = row[amount_idx].strip() if amount_idx < len(row) else "0"

            # Parse date YYYY-MM-DD or DD.MM.YYYY
            norm_date = current_iso_time()[:10]
            if re.match(r"^\d{2}\.\d{2}\.\d{4}", raw_date):
                parts = raw_date[:10].split(".")
                norm_date = f"{parts[2]}-{parts[1]}-{parts[0]}"
            elif re.match(r"^\d{4}-\d{2}-\d{2}", raw_date):
                norm_date = raw_date[:10]
            else:
                raise ValueError(f"Строка {row_idx}: дата операции не распознана.")
            try:
                date.fromisoformat(norm_date)
            except ValueError:
                raise ValueError(f"Строка {row_idx}: некорректная дата операции.") from None

            cents, direction = clean_amount_str(raw_amount)
            if cents <= 0:
                continue

            guessed_cat = guess_category(raw_desc, categories, direction)

            # Generate idempotency signature
            raw_sig = f"{norm_date}:{cents}:{direction}:{raw_desc.strip().lower()}"
            idem_key = "imp_" + hashlib.sha256(raw_sig.encode("utf-8")).hexdigest()[:16]
            legacy_keys = [idem_key]
            # Recognize identifiers created by the previous float-rounding parser.
            # This is compatibility lookup only; new money never uses float arithmetic.
            normalized_legacy = raw_amount.strip().replace("₽", "").replace("RUB", "").replace("руб", "").replace(" ", "").replace("\xa0", "").strip("()+-").replace(",", ".")
            try:
                old_cents = int(round(abs(float(normalized_legacy)) * 100))
                old_sig = f"{norm_date}:{old_cents}:{direction}:{raw_desc.strip().lower()}"
                old_key = "imp_" + hashlib.sha256(old_sig.encode("utf-8")).hexdigest()[:16]
                if old_key not in legacy_keys:
                    legacy_keys.append(old_key)
            except (ValueError, OverflowError):
                pass
            occurrences[raw_sig] += 1
            bank_transaction_id = row[bank_id_idx].strip() if 0 <= bank_id_idx < len(row) else None
            identity = "bank:" + bank_transaction_id if bank_transaction_id else raw_sig + ":occurrence:" + str(occurrences[raw_sig])

            parsed_items.append({
                "line_num": row_idx,
                "date": norm_date,
                "description": raw_desc,
                "amount_cents": cents,
                "amount_rub": cents_to_rubles(cents),
                "direction": direction,
                "category_id": guessed_cat["id"] if guessed_cat else None,
                "category_name": guessed_cat["name"] if guessed_cat else "Без категории",
                "idempotency_key": "imp_v2_" + hashlib.sha256(identity.encode("utf-8")).hexdigest(),
                "legacy_idempotency_key": idem_key,
                "legacy_idempotency_keys": legacy_keys,
                "occurrence": occurrences[raw_sig],
                "bank_transaction_id": bank_transaction_id,
                "identity_warning": None if bank_transaction_id else "Без ID банка одинаковые операции различаются по порядку в выписке; неполные перекрывающиеся выписки требуют сверки."
            })

        return parsed_items

    def commit_imported_items(
        self,
        items: List[Dict[str, Any]],
        account_id: str,
        owner_member_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Record verified preview items as double-entry transactions in the ledger.
        Deduplicates previously imported items via idempotency keys.
        """
        account = self.ledger.get_account(account_id)
        if not account:
            raise ValueError(f"Целевой счет {account_id} не найден.")

        expense_contra = self.ledger.get_account_by_code("5010")
        income_contra = self.ledger.get_account_by_code("4010")

        imported_count = 0
        skipped_count = 0
        errors = []

        for item in items:
            cents = item["amount_cents"]
            direction = item.get("direction", "EXPENSE")
            desc = item.get("description", "Импортированная операция")
            tx_date = item.get("date", current_iso_time()[:10])
            idem_key = item.get("idempotency_key")
            if not idem_key:
                errors.append({"line_num": item.get("line_num"), "message": "У операции нет идентификатора импорта."})
                continue
            idem_key = "import:" + account.id + ":" + idem_key
            cat_id = item.get("category_id")

            tx_id = generate_uuid()
            postings = []

            if direction == "EXPENSE":
                postings.append(Posting(
                    id=generate_uuid(),
                    transaction_id=tx_id,
                    account_id=expense_contra.id,
                    amount_cents=cents,
                    posting_type="DEBIT",
                    ownership_scope=account.ownership_scope,
                    category_id=cat_id
                ))
                postings.append(Posting(
                    id=generate_uuid(),
                    transaction_id=tx_id,
                    account_id=account.id,
                    amount_cents=cents,
                    posting_type="CREDIT",
                    ownership_scope=account.ownership_scope
                ))
            else:
                postings.append(Posting(
                    id=generate_uuid(),
                    transaction_id=tx_id,
                    account_id=account.id,
                    amount_cents=cents,
                    posting_type="DEBIT",
                    ownership_scope=account.ownership_scope
                ))
                postings.append(Posting(
                    id=generate_uuid(),
                    transaction_id=tx_id,
                    account_id=income_contra.id,
                    amount_cents=cents,
                    posting_type="CREDIT",
                    ownership_scope=account.ownership_scope,
                    category_id=cat_id
                ))

            tx = Transaction(
                id=tx_id,
                tx_date=tx_date,
                tx_type=direction,
                description=desc,
                created_by_member_id=owner_member_id,
                idempotency_key=idem_key,
                postings=postings
            )

            try:
                require_cents(cents)
                if direction not in ("INCOME", "EXPENSE"):
                    raise ValueError("Некорректное направление импортируемой операции.")
                legacy_key = item.get("legacy_idempotency_key")
                if legacy_key and item.get("occurrence", 1) == 1:
                    conn=self.ledger._get_conn()
                    try:
                        legacy=None
                        for candidate in item.get("legacy_idempotency_keys",[legacy_key]):
                            legacy=conn.execute("SELECT t.id,p.amount_cents FROM transactions t JOIN postings p ON p.transaction_id=t.id WHERE t.idempotency_key=? AND p.account_id=? LIMIT 1",(candidate,account.id)).fetchone()
                            if legacy:
                                break
                    finally:
                        self.ledger._close_if_local(conn)
                    if legacy:
                        if legacy["amount_cents"] != cents:
                            raise ValueError("Операция уже импортирована старым правилом округления. Нужна сверка суммы; повторная запись не создана.")
                        skipped_count += 1
                        continue
                res_id = self.ledger.record_transaction(tx, idempotency_key=idem_key)
                if res_id == tx_id:
                    imported_count += 1
                else:
                    skipped_count += 1
            except Exception as exc:
                errors.append({"line_num":item.get("line_num"),"message":str(exc)})

        overview = self.ledger.get_financial_overview()
        return {
            "status": "partial" if errors else "success",
            "imported_count": imported_count,
            "skipped_count": skipped_count,
            "error_count": len(errors),
            "errors": errors,
            "identity_warning": "Для выписок без ID банка неполные перекрывающиеся наборы одинаковых операций требуют ручной сверки." if any(not i.get("bank_transaction_id") for i in items) else None,
            "overview": overview
        }
