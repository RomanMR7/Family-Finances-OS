"""Deterministic credit estimates in integer minor units.

These are estimates using APR/12, HALF_UP interest, a 150 RUB minimum
floor and 30-day display months. They are not a bank statement or a
contractual accrual engine, and never write financial transactions.
"""
from datetime import date, timedelta
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP, localcontext

from family_finances_os.models import cents_to_rubles


def integer_amount(value, name="amount", allow_zero=True):
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name}: требуется целое число копеек.")
    if value < 0 or (not allow_zero and value == 0) or value > 9_000_000_000_000_000:
        raise ValueError(f"{name}: недопустимая сумма.")
    return value


def percentage(value, name, maximum=10000):
    if isinstance(value, bool):
        raise ValueError(f"{name}: недопустимая ставка.")
    try:
        number = Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError):
        raise ValueError(f"{name}: недопустимая ставка.") from None
    if not number.is_finite() or number < 0 or number > maximum:
        raise ValueError(f"{name}: ставка должна быть от 0 до {maximum}%.")
    return number


def validate_terms(interest_rate_percent=24.8, grace_period_days=120,
                   grace_due_date=None, min_payment_percent=3.0,
                   late_penalty_rate_percent=36.0):
    apr = percentage(interest_rate_percent, "Годовая ставка")
    minimum = percentage(min_payment_percent, "Минимальный платёж", 100)
    penalty = percentage(late_penalty_rate_percent, "Неустойка")
    if isinstance(grace_period_days, bool) or not isinstance(grace_period_days, int) or not 0 <= grace_period_days <= 3650:
        raise ValueError("Льготный период должен быть целым числом дней от 0 до 3650.")
    due = None
    if grace_due_date is not None and str(grace_due_date).strip():
        clean = str(grace_due_date).strip()
        try:
            due = date.fromisoformat(clean).isoformat()
        except ValueError:
            raise ValueError("Дата окончания льготного периода должна быть YYYY-MM-DD.") from None
    return {"interest_rate_percent": float(apr), "grace_period_days": grace_period_days,
            "grace_due_date": due, "min_payment_percent": float(minimum),
            "late_penalty_rate_percent": float(penalty)}


def rounded(value):
    return int(value.quantize(Decimal("1"), rounding=ROUND_HALF_UP))


def _simulate(debt, monthly_rate, payment, today, horizon=360):
    remaining, accrued, paid = debt, 0, 0
    schedule = []
    status = "PAID_OFF" if not debt else "HORIZON_LIMIT"
    for month in range(1, horizon + 1):
        if remaining == 0:
            break
        interest = rounded(Decimal(remaining) * monthly_rate)
        requested = payment(remaining)
        actual = min(remaining + interest, requested)
        ending = remaining + interest - actual
        schedule.append({"month": month, "opening_cents": remaining,
                         "interest_cents": interest, "payment_cents": actual,
                         "closing_cents": ending})
        accrued += interest
        paid += actual
        if ending == 0:
            remaining = 0
            status = "PAID_OFF"
            break
        if actual <= interest:
            remaining = ending
            status = "NON_AMORTIZING"
            break
        remaining = ending
    paid_off = remaining == 0
    months = len(schedule) if paid_off else None
    total_interest = accrued if paid_off else None
    return {
        "status": status, "paid_off": paid_off, "remaining_cents": remaining,
        "remaining_rub": cents_to_rubles(remaining), "months_simulated": len(schedule),
        "months_to_payoff": months, "days_to_payoff": months * 30 if paid_off else None,
        "payoff_date": (today + timedelta(days=months * 30)).isoformat() if paid_off else None,
        "total_paid_cents": paid if paid_off else None,
        "total_paid_rub": cents_to_rubles(paid) if paid_off else None,
        "total_interest_cents": total_interest,
        "total_interest_rub": cents_to_rubles(total_interest) if paid_off else None,
        "paid_during_simulation_cents": paid,
        "interest_during_simulation_cents": accrued,
        "last_payment_cents": schedule[-1]["payment_cents"] if schedule else 0,
        "schedule": schedule,
    }


def payoff_scenarios(debt_cents, interest_rate_percent=24.8, min_payment_percent=3.0,
                     grace_period_days=120, grace_due_date=None, as_of_date=None,
                     custom_payment_cents=None, custom_payment_percent=None):
    debt = integer_amount(debt_cents, "Долг")
    terms = validate_terms(interest_rate_percent, grace_period_days, grace_due_date, min_payment_percent)
    today = date.fromisoformat(as_of_date) if as_of_date else date.today()
    apr = Decimal(str(terms["interest_rate_percent"]))
    minimum_pct = Decimal(str(terms["min_payment_percent"]))
    custom = None
    if custom_payment_cents is not None:
        custom = integer_amount(custom_payment_cents, "Платёж", allow_zero=False)
    elif custom_payment_percent is not None:
        pct = percentage(custom_payment_percent, "Платёж в процентах", 100)
        if pct <= 0:
            raise ValueError("Процент платежа должен быть больше нуля.")
        custom = rounded(Decimal(debt) * pct / 100)
        if debt and custom == 0:
            raise ValueError("Указанный процент меньше одной копейки.")

    with localcontext() as ctx:
        ctx.prec = 50
        monthly = apr / 1200
        minimum_payment = lambda remaining: min(remaining, max(15000, rounded(Decimal(remaining) * minimum_pct / 100)))
        minimum = _simulate(debt, monthly, minimum_payment, today)
        first = minimum["schedule"][0]["payment_cents"] if minimum["schedule"] else 0
        minimum.update(first_payment_cents=first, first_payment_rub=cents_to_rubles(first),
                       payment_percent=float(minimum_pct))
        due = date.fromisoformat(terms["grace_due_date"]) if terms["grace_due_date"] else None
        days_left = (due - today).days if due else None
        grace_status = "PAID_OFF" if not debt else "UNKNOWN" if due is None else "ACTIVE" if days_left >= 0 else "EXPIRED"
        grace_active = grace_status == "ACTIVE"
        grace = {
            "status": grace_status, "days_left": max(0, days_left) if days_left is not None else None,
            "due_date": terms["grace_due_date"], "is_active": grace_active,
            "required_full_payment_rub": cents_to_rubles(debt),
            "total_interest_cents": 0 if grace_active or not debt else None,
            "total_interest_rub": "0.00" if grace_active or not debt else None,
            "savings_rub": minimum["total_interest_rub"] if grace_active else None,
            "note": ("Задолженность отсутствует." if not debt else
                     "Расчётный сценарий погашения до указанной даты; условия грейса проверьте по договору." if grace_active else
                     "Дата грейса неизвестна; беспроцентный период не подтверждён." if due is None else
                     "Указанная дата грейса истекла; условия начислений определяет договор."),
        }
        accelerated = []
        for horizon in (3, 6, 12) if debt else ():
            # Integer binary search solves the same monthly-rounding model as
            # the displayed schedule. The last actual payment clears the cents.
            low, high = 1, debt + rounded(Decimal(debt) * monthly)
            while low < high:
                mid = (low + high) // 2
                candidate = _simulate(debt, monthly, lambda _: mid, today, horizon)
                if candidate["paid_off"]:
                    high = mid
                else:
                    low = mid + 1
            payment = low
            scenario = _simulate(debt, monthly, lambda _: payment, today, horizon)
            saving = (max(0, minimum["total_interest_cents"] - scenario["total_interest_cents"])
                      if minimum["paid_off"] and scenario["paid_off"] else None)
            scenario.update(months=horizon, days=horizon * 30,
                            target_date=(today + timedelta(days=horizon * 30)).isoformat(),
                            monthly_payment_cents=payment, monthly_payment_rub=cents_to_rubles(payment),
                            monthly_payment_percent=float((Decimal(payment) / debt * 100).quantize(Decimal("0.1"), rounding=ROUND_HALF_UP)),
                            interest_savings_cents=saving,
                            interest_savings_rub=cents_to_rubles(saving) if saving is not None else None,
                            days_saved=max(0, minimum["days_to_payoff"] - scenario["days_to_payoff"]) if minimum["paid_off"] else None,
                            label={3: "За 3 месяца", 6: "За 6 месяцев", 12: "За 12 месяцев"}[horizon])
            accelerated.append(scenario)
        custom_scenario = None
        if custom is not None:
            custom_scenario = _simulate(debt, monthly, lambda _: custom, today)
            saving = (max(0, minimum["total_interest_cents"] - custom_scenario["total_interest_cents"])
                      if minimum["paid_off"] and custom_scenario["paid_off"] else None)
            custom_scenario.update(monthly_payment_cents=custom,
                                   monthly_payment_rub=cents_to_rubles(custom),
                                   payment_percent=float(custom_payment_percent) if custom_payment_percent is not None else
                                   float((Decimal(custom) / debt * 100).quantize(Decimal("0.1"), rounding=ROUND_HALF_UP)) if debt else 0,
                                   interest_savings_cents=saving,
                                   interest_savings_rub=cents_to_rubles(saving) if saving is not None else None,
                                   days_saved=max(0, minimum["days_to_payoff"] - custom_scenario["days_to_payoff"]) if minimum["paid_off"] and custom_scenario["paid_off"] else None)
    return {"debt_cents": debt, "debt_rub": cents_to_rubles(debt),
            "interest_rate_percent": float(apr), "min_payment_percent": float(minimum_pct),
            "model": "ESTIMATE_APR12_HALF_UP_30_DAY_MONTHS", "is_estimate": True,
            "assumptions": "APR/12; округление процентов HALF_UP до копейки; минимум 150 ₽; месяц для отображения 30 дней; будущие покупки и комиссии не включены.",
            "grace_scenario": grace, "minimum_scenario": minimum,
            "accelerated_scenarios": accelerated, "custom_scenario": custom_scenario}


def banking_metrics(debt_cents, credit_limit_cents=0, interest_rate_percent=24.8,
                    grace_period_days=120, grace_due_date=None, min_payment_percent=3.0,
                    late_penalty_rate_percent=36.0, as_of_date=None):
    debt = integer_amount(debt_cents, "Долг")
    limit = integer_amount(credit_limit_cents, "Кредитный лимит")
    terms = validate_terms(interest_rate_percent, grace_period_days, grace_due_date,
                           min_payment_percent, late_penalty_rate_percent)
    today = date.fromisoformat(as_of_date) if as_of_date else date.today()
    due = date.fromisoformat(terms["grace_due_date"]) if terms["grace_due_date"] else None
    remaining = (due - today).days if due else None
    min_amount = min(debt, max(15000, rounded(Decimal(debt) * Decimal(str(min_payment_percent)) / 100))) if debt else 0
    status = ("PAID_OFF" if not debt else "UNKNOWN" if remaining is None else
              "OVERDUE" if remaining < 0 else "PAYMENT_DUE_SOON" if remaining <= 5 else "GRACE_ACTIVE")
    overdue = abs(remaining) if status == "OVERDUE" else 0
    labels = {"PAID_OFF": "Задолженность отсутствует", "UNKNOWN": "Дата грейса не указана",
              "OVERDUE": f"Указанная дата истекла {overdue} дн. назад",
              "PAYMENT_DUE_SOON": f"До указанной даты {remaining} дн.",
              "GRACE_ACTIVE": f"До указанной даты грейса {remaining} дн."}
    with localcontext() as ctx:
        ctx.prec = 50
        daily = Decimal(str(terms["interest_rate_percent"])) / 36500
        daily_penalty = Decimal(str(terms["late_penalty_rate_percent"])) / 36500
        interest = rounded(Decimal(debt) * daily * overdue)
        penalty = rounded(Decimal(debt) * daily_penalty * overdue)
        sim_interest = rounded(Decimal(debt) * daily * 30)
        sim_penalty = rounded(Decimal(debt) * daily_penalty * 30)
    warning = ("Задолженность отсутствует." if not debt else
               "Дата грейса неизвестна. Укажите её по выписке; наличие беспроцентного периода не подтверждено." if remaining is None else
               "Срок и начисления показаны по введённым условиям. Точный обязательный платёж, грейс и неустойку сверяйте с выпиской банка.")
    if status == "PAYMENT_DUE_SOON":
        warning = "Срочно проверьте приближающуюся дату платежа. " + warning
    result = {"debt_cents": debt, "debt_rub": float(cents_to_rubles(debt)),
              "debt_formatted": cents_to_rubles(debt), "credit_limit_cents": limit,
              "credit_limit_rub": float(cents_to_rubles(limit)), "credit_limit_formatted": cents_to_rubles(limit),
              **terms, "min_payment_cents": min_amount, "min_payment_rub": float(cents_to_rubles(min_amount)),
              "min_payment_formatted": cents_to_rubles(min_amount), "days_remaining": remaining,
              "overdue_days": overdue, "status": status, "status_label": labels[status],
              "status_color": {"PAID_OFF": "gray", "UNKNOWN": "gray", "OVERDUE": "red", "PAYMENT_DUE_SOON": "yellow", "GRACE_ACTIVE": "green"}[status],
              "is_urgent": status in ("OVERDUE", "PAYMENT_DUE_SOON"), "is_overdue": status == "OVERDUE",
              "warning_message": warning, "is_estimate": True,
              "accruals_are_posted": False,
              "accrued_overdue_interest_cents": interest, "accrued_overdue_penalty_cents": penalty,
              "current_debt_with_accruals_cents": debt + interest + penalty,
              "simulation_30d_interest_cents": sim_interest, "simulation_30d_penalty_cents": sim_penalty,
              "simulation_30d_extra_cents": sim_interest + sim_penalty,
              "simulation_30d_total_cents": debt + sim_interest + sim_penalty,
              "payoff_scenarios": payoff_scenarios(debt, terms["interest_rate_percent"], terms["min_payment_percent"],
                                                  terms["grace_period_days"], terms["grace_due_date"], as_of_date)}
    for key in ("accrued_overdue_interest", "accrued_overdue_penalty", "current_debt_with_accruals",
                "simulation_30d_interest", "simulation_30d_penalty", "simulation_30d_extra", "simulation_30d_total"):
        result[key + "_rub"] = float(cents_to_rubles(result[key + "_cents"]))
    return result
