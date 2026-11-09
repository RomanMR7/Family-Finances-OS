"""
Family Finances OS - Domain Models & Precision Arithmetic
"""
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal, ROUND_HALF_UP
from typing import List, Optional


def rubles_to_cents(amount_rub: float | str | Decimal) -> int:
    """
    Safely convert rubles to integer cents without floating-point inaccuracies.
    Example: 100.50 -> 10050, '1250.99' -> 125099
    """
    dec = Decimal(str(amount_rub))
    cents = (dec * 100).quantize(Decimal("1"), rounding=ROUND_HALF_UP)
    return int(cents)


def cents_to_rubles(cents: int) -> str:
    """Format integer cents as rubles string: 10050 -> '100.50'"""
    dec = Decimal(cents) / Decimal(100)
    return f"{dec:.2f}"


def generate_uuid() -> str:
    """Generate standard UUID string."""
    return str(uuid.uuid4())


def current_iso_time() -> str:
    """Get current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


@dataclass
class User:
    id: str
    username: str
    display_name: str
    role: str  # 'OWNER', 'ADULT', 'CHILD', 'VIEWER'
    password_hash: bytes
    salt: bytes
    is_active: bool = True
    created_at: str = field(default_factory=current_iso_time)


@dataclass
class Member:
    id: str
    user_id: Optional[str]
    display_name: str
    role: str
    color_hex: str = "#2563EB"
    created_at: str = field(default_factory=current_iso_time)


@dataclass
class Account:
    id: str
    code: str
    name: str
    account_type: str  # 'ASSET', 'LIABILITY', 'EQUITY', 'INCOME', 'EXPENSE'
    subtype: str  # 'DEBIT_CARD', 'CASH', 'CHECKING', 'SAVINGS', 'DEPOSIT', 'CREDIT_CARD', etc.
    currency: str = "RUB"
    ownership_scope: str = "COMMON"  # 'COMMON', 'PERSONAL_HUSBAND', 'PERSONAL_WIFE', 'PERSONAL_CHILD', etc.
    owner_member_id: Optional[str] = None
    description: Optional[str] = None
    credit_limit_cents: int = 0
    initial_balance_cents: int = 0
    is_active: bool = True
    created_at: str = field(default_factory=current_iso_time)


@dataclass
class Posting:
    id: str
    transaction_id: str
    account_id: str
    amount_cents: int
    posting_type: str  # 'DEBIT' or 'CREDIT'
    ownership_scope: str = "COMMON"
    purpose_allocation: str = "SAFE_TO_SPEND"
    note: Optional[str] = None
    category_id: Optional[str] = None
    created_at: str = field(default_factory=current_iso_time)


@dataclass
class Category:
    id: str
    name: str
    category_type: str  # 'INCOME', 'EXPENSE'
    parent_id: Optional[str] = None
    icon: str = "tag"
    sort_order: int = 0
    is_active: bool = True


@dataclass
class Obligation:
    id: str
    name: str
    amount_cents: int
    due_day: int
    category_id: Optional[str] = None
    payment_account_id: Optional[str] = None
    note: Optional[str] = None
    is_active: bool = True
    created_at: str = field(default_factory=current_iso_time)


@dataclass
class ObligationPayment:
    id: str
    obligation_id: str
    month_year: str
    paid_amount_cents: int
    transaction_id: Optional[str] = None
    paid_at: str = field(default_factory=current_iso_time)


@dataclass
class Goal:
    id: str
    name: str
    target_amount_cents: int
    current_amount_cents: int = 0
    target_date: Optional[str] = None
    account_id: Optional[str] = None
    category_id: Optional[str] = None
    icon: str = "🎯"
    note: Optional[str] = None
    is_completed: bool = False
    is_active: bool = True
    created_at: str = field(default_factory=current_iso_time)


@dataclass
class GoalContribution:
    id: str
    goal_id: str
    amount_cents: int
    transaction_id: Optional[str] = None
    source_account_id: Optional[str] = None
    note: Optional[str] = None
    created_at: str = field(default_factory=current_iso_time)


@dataclass
class Envelope:
    """
    Savings Envelope / Virtual Piggy Bank (Конверт-копилка).
    Enables envelope budgeting where money is allocated into dedicated visual buckets/piggy banks.
    """
    id: str
    name: str
    target_amount_cents: int = 0
    current_amount_cents: int = 0
    icon: str = "✉️"
    color: str = "#3b82f6"
    linked_account_id: Optional[str] = None
    category_id: Optional[str] = None
    note: Optional[str] = None
    is_active: bool = True
    created_at: str = field(default_factory=current_iso_time)


@dataclass
class EnvelopeOperation:
    """
    Operations on Envelopes: DEPOSIT (положить в конверт), WITHDRAW (взять из конверта), TRANSFER (переложить).
    """
    id: str
    envelope_id: str
    operation_type: str  # 'DEPOSIT', 'WITHDRAW', 'TRANSFER'
    amount_cents: int
    source_account_id: Optional[str] = None
    destination_account_id: Optional[str] = None
    target_envelope_id: Optional[str] = None
    note: Optional[str] = None
    member_id: Optional[str] = None
    created_at: str = field(default_factory=current_iso_time)


@dataclass
class Transaction:
    id: str
    tx_date: str
    tx_type: str  # 'INCOME', 'EXPENSE', 'TRANSFER', 'CREDIT_PURCHASE', 'CREDIT_PAYMENT', 'ADJUSTMENT', etc.
    description: str
    created_by_member_id: Optional[str] = None
    idempotency_key: Optional[str] = None
    payload_hash: Optional[str] = None
    postings: List[Posting] = field(default_factory=list)
    is_voided: bool = False
    voided_reason: Optional[str] = None
    reversal_of_id: Optional[str] = None
    created_at: str = field(default_factory=current_iso_time)

    def validate_double_entry(self) -> bool:
        """
        Verify the fundamental accounting equation for this transaction:
        Sum of Debits MUST strictly equal Sum of Credits in integer cents.
        """
        total_debit = sum(p.amount_cents for p in self.postings if p.posting_type == "DEBIT")
        total_credit = sum(p.amount_cents for p in self.postings if p.posting_type == "CREDIT")
        return total_debit == total_credit and total_debit > 0
