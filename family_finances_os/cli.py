"""
Family Finances OS - Command Line Interface (CLI)
Provides full management, setup, accounting transactions, transfers, diagnostics,
and envelope encryption operations (AES-256-GCM + PBKDF2-HMAC-SHA256).
"""
import argparse
import getpass
import shutil
import sqlite3
import sys
from pathlib import Path

# Ensure UTF-8 output on Windows console
if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

from family_finances_os.config import APP_NAME, APP_VERSION, DB_PATH, ENC_DB_PATH, STRICT_ENCRYPTION
from family_finances_os.db import init_database, check_db_health, GLOBAL_STORAGE, EncryptedDatabaseStorage
from family_finances_os.security import create_envelope, open_envelope, fast_save_envelope
from family_finances_os.auth import AuthService
from family_finances_os.ledger import LedgerEngine
from family_finances_os.models import (
    Transaction,
    Posting,
    rubles_to_cents,
    cents_to_rubles,
    generate_uuid,
    current_iso_time
)


def print_banner():
    print("=" * 65)
    print(f" {APP_NAME} v{APP_VERSION} ")
    print(" Закрытая автономная система управления финансами семьи")
    print("=" * 65)


def ensure_unlocked(password_arg: str = None) -> bool:
    """Helper to ensure storage is unlocked if encrypted on disk."""
    if not (ENC_DB_PATH.exists() and not DB_PATH.exists()):
        return True
    if GLOBAL_STORAGE.is_unlocked():
        return True

    password = password_arg or getpass.getpass("База зашифрована. Введите мастер-пароль: ")
    try:
        GLOBAL_STORAGE.open(password)
        return True
    except PermissionError:
        print("[ОШИБКА] Неверный мастер-пароль или файл базы данных поврежден.")
        sys.exit(1)
    except Exception as e:
        print(f"[ОШИБКА] Сбой разблокировки: {e}")
        sys.exit(1)


def cmd_status(args):
    print_banner()
    health = check_db_health()
    is_enc = ENC_DB_PATH.exists()
    is_locked = is_enc and not GLOBAL_STORAGE.is_unlocked() and not DB_PATH.exists()
    has_owner = False

    if not is_locked:
        try:
            auth = AuthService()
            has_owner = auth.has_owner()
        except Exception:
            has_owner = False

    enc_status = "НЕ ЗАШИФРОВАНО (Plaintext)"
    if GLOBAL_STORAGE.is_unlocked():
        enc_status = "РАЗБЛОКИРОВАНО (В оперативной памяти, AES-256-GCM)"
    elif is_enc:
        enc_status = f"ЗАБЛОКИРОВАНО ({ENC_DB_PATH.stat().st_size} байт на диске)"

    print(f"Путь к файлу БД:       {health.get('db_file', str(DB_PATH))}")
    print(f"Статус шифрования:     {enc_status}")
    print(f"Проверка целостности:  {health.get('integrity', 'Неизвестно')}")
    print(f"Количество таблиц:     {health.get('table_count', 'N/A')}")
    print(f"Версия схемы БД:       {health.get('schema_version', 'N/A')}")
    print(f"Владелец семьи создан: {'ДА' if has_owner else 'НЕТ (требуется первичная настройка)'}")
    print(f"Алгоритм защиты:       AES-256-GCM + PBKDF2 (600 000 итераций)")
    print(f"Режим работы:          100% Автономный / Локальный (Offline)")
    print("=" * 65)


def cmd_init(args):
    print_banner()
    print("Инициализация локальной базы данных SQLite...")
    init_database()
    ledger = LedgerEngine()
    created = ledger.seed_default_chart_of_accounts()
    print(f"База успешно создана: {DB_PATH}")
    print(f"Создан базовый план счетов ({len(created)} счетов). Режим журнала: WAL.")


def cmd_setup_owner(args):
    print_banner()
    ensure_unlocked(getattr(args, "password", None))

    if not DB_PATH.exists() and not GLOBAL_STORAGE.is_unlocked():
        init_database()

    ledger = LedgerEngine()
    ledger.seed_default_chart_of_accounts()
    auth = AuthService()

    if auth.has_owner():
        print("[ОШИБКА] Владелец семьи уже зарегистрирован!")
        sys.exit(1)

    username = args.username or input("Введите логин владельца [admin]: ").strip() or "admin"
    display_name = args.display_name or input("Введите отображаемое имя [Глава семьи]: ").strip() or "Глава семьи"
    password = args.password
    if not password:
        password = getpass.getpass("Введите мастер-пароль (не менее 6 символов): ")

    try:
        res = auth.create_owner(username, display_name, password)
        print(f"\n[УСПЕХ] Владелец семьи '{res['display_name']}' (логин: {res['username']}) успешно создан!")
        print("Пароль надежно хэширован алгоритмом PBKDF2-HMAC-SHA256 (600 000 итераций).")
    except Exception as e:
        print(f"\n[ОШИБКА] Не удалось создать владельца: {e}")
        sys.exit(1)


def cmd_login(args):
    print_banner()
    ensure_unlocked(getattr(args, "password", None))
    auth = AuthService()
    username = args.username or input("Логин: ").strip()
    password = args.password
    if not password:
        password = getpass.getpass("Пароль: ")

    user = auth.authenticate(username, password)
    if user:
        print(f"\n[УСПЕХ] Вход выполнен! Добро пожаловать, {user['display_name']} ({user['role']}).")
        print(f"Активная локальная сессия: {user['session_token'][:16]}...")
    else:
        print("\n[ОТКАЗ] Неверное имя пользователя или пароль.")
        sys.exit(1)


def cmd_add_transaction(args):
    print_banner()
    ensure_unlocked(getattr(args, "password", None))
    ledger = LedgerEngine()
    amount_cents = rubles_to_cents(args.amount)
    if amount_cents <= 0:
        print("[ОШИБКА] Сумма операции должна быть строго больше нуля.")
        sys.exit(1)

    asset_acc = ledger.get_account_by_code(args.account_code or "1010")
    if not asset_acc:
        print(f"[ОШИБКА] Денежный счет {args.account_code} не найден.")
        sys.exit(1)

    category_code = args.category_code
    if not category_code:
        category_code = "4010" if args.tx_type == "INCOME" else "5010"
    cat_acc = ledger.get_account_by_code(category_code)
    if not cat_acc:
        print(f"[ОШИБКА] Статья {category_code} не найдена.")
        sys.exit(1)

    desc = args.description or ("Доход" if args.tx_type == "INCOME" else "Расход")

    # If paying common expense with personal card:
    if getattr(args, "personal_for_common", False):
        try:
            tx_id = ledger.record_common_expense_from_personal_card(
                personal_account_id=asset_acc.id,
                category_account_id=cat_acc.id,
                amount_cents=amount_cents,
                description=desc
            )
            print(f"\n[УСПЕХ] Общая покупка '{desc}' с личной карты '{asset_acc.name}' на сумму {cents_to_rubles(amount_cents)} ₽ сохранена!")
            print(f"ID транзакции: {tx_id} (автоматический долг НЕ создается)")
            return
        except Exception as e:
            print(f"[ОШИБКА] Сбой: {e}")
            sys.exit(1)

    tx_id = generate_uuid()
    tx_date = current_iso_time()[:10]
    postings = []
    if args.tx_type == "EXPENSE":
        postings.append(Posting(id=generate_uuid(), transaction_id=tx_id, account_id=cat_acc.id, amount_cents=amount_cents, posting_type="DEBIT", ownership_scope=asset_acc.ownership_scope))
        postings.append(Posting(id=generate_uuid(), transaction_id=tx_id, account_id=asset_acc.id, amount_cents=amount_cents, posting_type="CREDIT", ownership_scope=asset_acc.ownership_scope))
    else:
        postings.append(Posting(id=generate_uuid(), transaction_id=tx_id, account_id=asset_acc.id, amount_cents=amount_cents, posting_type="DEBIT", ownership_scope=asset_acc.ownership_scope))
        postings.append(Posting(id=generate_uuid(), transaction_id=tx_id, account_id=cat_acc.id, amount_cents=amount_cents, posting_type="CREDIT", ownership_scope=asset_acc.ownership_scope))

    tx = Transaction(id=tx_id, tx_date=tx_date, tx_type=args.tx_type, description=desc, created_by_member_id=None, postings=postings)
    try:
        ledger.record_transaction(tx)
        print(f"\n[УСПЕХ] Финансовая операция '{desc}' на сумму {cents_to_rubles(amount_cents)} ₽ сохранена!")
        print(f"ID транзакции: {tx.id}")
    except Exception as e:
        print(f"[ОШИБКА] Не удалось записать операцию: {e}")
        sys.exit(1)


def cmd_transfer(args):
    print_banner()
    ensure_unlocked(getattr(args, "password", None))
    ledger = LedgerEngine()
    from_acc = ledger.get_account_by_code(args.from_code)
    to_acc = ledger.get_account_by_code(args.to_code)

    if not from_acc:
        print(f"[ОШИБКА] Счет списания {args.from_code} не найден.")
        sys.exit(1)
    if not to_acc:
        print(f"[ОШИБКА] Счет зачисления {args.to_code} не найден.")
        sys.exit(1)

    amount_cents = rubles_to_cents(args.amount)
    if amount_cents <= 0:
        print("[ОШИБКА] Сумма перевода должна быть больше нуля.")
        sys.exit(1)

    desc = args.description or f"Перевод с {from_acc.name} на {to_acc.name}"

    try:
        tx_id = ledger.record_transfer(
            from_account_id=from_acc.id,
            to_account_id=to_acc.id,
            amount_cents=amount_cents,
            description=desc
        )
        print(f"\n[УСПЕХ] Внутренний перевод на сумму {cents_to_rubles(amount_cents)} ₽ выполнен успешно!")
        print(f"Со счета:      {from_acc.name} ({from_acc.code})")
        print(f"На счет:        {to_acc.name} ({to_acc.code})")
        print(f"ID транзакции:  {tx_id}")
    except Exception as e:
        print(f"[ОШИБКА] Перевод отклонен: {e}")
        sys.exit(1)


def cmd_create_account(args):
    print_banner()
    ensure_unlocked(getattr(args, "password", None))
    ledger = LedgerEngine()
    account_type = "LIABILITY" if args.subtype == "CREDIT_CARD" else "ASSET"
    init_cents = rubles_to_cents(args.initial_balance or "0")
    limit_cents = rubles_to_cents(args.credit_limit or "0")

    try:
        acc = ledger.create_account(
            name=args.name,
            account_type=account_type,
            subtype=args.subtype,
            ownership_scope=args.scope,
            code=args.code,
            description=args.description,
            credit_limit_cents=limit_cents,
            initial_balance_cents=init_cents
        )
        print(f"\n[УСПЕХ] Счет '{acc.name}' (код: {acc.code}) успешно создан!")
        print(f"Тип: {acc.subtype} | Принадлежность: {acc.ownership_scope}")
        if init_cents > 0:
            print(f"Начальный баланс: {cents_to_rubles(init_cents)} ₽ (проводка через 3010)")
        if limit_cents > 0:
            print(f"Кредитный лимит: {cents_to_rubles(limit_cents)} ₽")
    except Exception as e:
        print(f"[ОШИБКА] Не удалось создать счет: {e}")
        sys.exit(1)


def cmd_overview(args):
    print_banner()
    ensure_unlocked(getattr(args, "password", None))
    ledger = LedgerEngine()
    overview = ledger.get_financial_overview()

    print(f" ДАТА СВОДКИ: {overview['as_of_date']}")
    print("-" * 65)

    if overview.get("is_deficit"):
        print(f" [!] ВНИМАНИЕ: ДЕФИЦИТ СЕМЕЙНОГО БЮДЖЕТА: -{overview['deficit_rub']} ₽ [!]")
        print(f" Доступно к тратам:     0.00 ₽ (ДЕФИЦИТ: -{overview['deficit_rub']} ₽)")
    else:
        print(f" Доступно к тратам:     {overview['common_safe_to_spend_rub']} ₽ (Safe-to-Spend)")

    print(f" Общие ликвидные активы: {overview['common_liquid_assets_rub']} ₽")
    print(f" Подушка безопасности:  {overview['emergency_reserves_rub']} ₽")
    print(f" Чистый капитал семьи:  {overview['family_net_worth_rub']} ₽")
    print(f" Личные карты (инфо):   Муж: {overview['husband_personal_balance_rub']} ₽ | Жена: {overview['wife_personal_balance_rub']} ₽")

    cc = overview["credit_cards"]
    print(f" Кредитные карты:       Долг: {cc['total_debt_rub']} ₽ (Лимит: {cc['total_limit_rub']} ₽, Доступно: {cc['available_limit_rub']} ₽)")

    print("-" * 65)
    print(f" {'КОД':<6} | {'СЧЕТ':<26} | {'ТИП':<11} | {'ОСТАТОК':>12}")
    print("-" * 65)
    for a in overview["accounts"]:
        print(f" {a['code']:<6} | {a['name']:<26} | {a['subtype']:<11} | {a['balance_rub']:>10} ₽")
    print("=" * 65)


def cmd_migrate_to_encrypted(args):
    print_banner()
    print("Миграция базы данных на конвертное шифрование AES-256-GCM...")

    if not DB_PATH.exists():
        print(f"[ОШИБКА] Исходная незашифрованная база данных {DB_PATH} не найдена.")
        sys.exit(1)

    password = args.password
    if not password:
        password = getpass.getpass("Введите мастер-пароль для шифрования (не менее 6 символов): ")
    if len(password) < 6:
        print("[ОШИБКА] Мастер-пароль должен содержать минимум 6 символов.")
        sys.exit(1)

    # 1. WAL Checkpoint & Integrity Check
    print("1. Контрольная точка журнала WAL и перевод в автономный режим (DELETE)...")
    check_conn = sqlite3.connect(str(DB_PATH))
    check_conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
    check_conn.execute("PRAGMA journal_mode = DELETE;")
    check_conn.commit()
    cur = check_conn.cursor()
    cur.execute("PRAGMA integrity_check;")
    res = cur.fetchone()[0]
    if res != "ok":
        print(f"[ОШИБКА] Целостность исходной базы нарушена: {res}")
        check_conn.close()
        sys.exit(1)
    check_conn.close()

    # 2. Envelope Encryption
    print("2. Создание конвертного шифрования (KEK PBKDF2 600k + DEK AES-256-GCM)...")
    raw_bytes = DB_PATH.read_bytes()
    container, dek, salt, kek_nonce, enc_dek = create_envelope(raw_bytes, password)

    # 3. Decryption Verification
    print("3. Проверочная расшифровка и верификация схемы в оперативной памяти...")
    verify_bytes, v_dek, _, _, _ = open_envelope(container, password)
    v_conn = sqlite3.connect(":memory:")
    v_conn.deserialize(verify_bytes)
    v_cur = v_conn.cursor()
    v_cur.execute("PRAGMA integrity_check;")
    if v_cur.fetchone()[0] != "ok":
        print("[ОШИБКА] Проверочная расшифровка не прошла проверку целостности!")
        v_conn.close()
        sys.exit(1)
    v_conn.close()

    # 4. Atomic Write Container
    print("4. Атомарная запись зашифрованного контейнера на диск...")
    EncryptedDatabaseStorage(ENC_DB_PATH)._write_container_atomically(container)

    # 5. Backup and Secure Shred Plaintext DB
    print("5. Создание резервной копии и безопасное удаление открытого файла БД...")
    backup_path = DB_PATH.with_suffix(".db.plaintext_backup")
    shutil.copy2(DB_PATH, backup_path)

    # Shred original plaintext file
    file_size = DB_PATH.stat().st_size
    with open(DB_PATH, "wb") as f:
        f.write(b"\x00" * file_size)
        f.flush()
    DB_PATH.unlink()

    # Remove WAL sidecars
    wal_path = DB_PATH.with_name(f"{DB_PATH.name}-wal")
    shm_path = DB_PATH.with_name(f"{DB_PATH.name}-shm")
    if wal_path.exists(): wal_path.unlink()
    if shm_path.exists(): shm_path.unlink()

    print("\n" + "=" * 65)
    print("[УСПЕХ] МИГРАЦИЯ УСПЕШНО ЗАВЕРШЕНА!")
    print(f"Зашифрованный файл:  {ENC_DB_PATH} ({len(container)} байт)")
    print(f"Резервная копия:     {backup_path}")
    print("Открытый файл SQLite стёрт с диска (Zero-Fill Shred).")
    print("=" * 65)


def cmd_unlock_db(args):
    print_banner()
    if not ENC_DB_PATH.exists():
        print(f"[ОШИБКА] Зашифрованный файл {ENC_DB_PATH} не найден.")
        sys.exit(1)

    password = args.password or getpass.getpass("Введите мастер-пароль: ")
    try:
        GLOBAL_STORAGE.open(password)
        print("\n[УСПЕХ] База данных успешно расшифрована в оперативную память!")
        cmd_overview(args)
    except PermissionError:
        print("\n[ОТКАЗ] Неверный мастер-пароль.")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ОШИБКА] Сбой: {e}")
        sys.exit(1)


def cmd_change_password(args):
    print_banner()
    if not ENC_DB_PATH.exists():
        print(f"[ОШИБКА] Зашифрованный файл {ENC_DB_PATH} не найден.")
        sys.exit(1)

    old_pwd = args.old_password or getpass.getpass("Введите текущий мастер-пароль: ")
    new_pwd = args.new_password or getpass.getpass("Введите НОВЫЙ мастер-пароль (не менее 6 символов): ")
    if len(new_pwd) < 6:
        print("[ОШИБКА] Новый пароль должен быть не менее 6 символов.")
        sys.exit(1)

    try:
        GLOBAL_STORAGE.change_password(old_pwd, new_pwd)
        print("\n[УСПЕХ] Мастер-пароль успешно изменен! Ключ шифрования DEK перешифрован новым KEK.")
    except PermissionError:
        print("\n[ОТКАЗ] Неверный текущий пароль.")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ОШИБКА] Сбой: {e}")
        sys.exit(1)


def cmd_web(args):
    from family_finances_os.web_server import start_server
    start_server(args.port)


def main():
    parser = argparse.ArgumentParser(description=f"{APP_NAME} CLI")
    subparsers = parser.add_subparsers(dest="command")

    # status
    subparsers.add_parser("status", help="Проверить статус локальной базы данных")

    # init
    subparsers.add_parser("init", help="Инициализировать схему базы данных")

    # setup-owner
    p_setup = subparsers.add_parser("setup-owner", help="Создать первого владельца")
    p_setup.add_argument("--username", "-u", help="Имя пользователя")
    p_setup.add_argument("--display-name", "-n", help="Отображаемое имя")
    p_setup.add_argument("--password", "-p", help="Пароль")

    # login
    p_login = subparsers.add_parser("login", help="Проверить вход по паролю")
    p_login.add_argument("--username", "-u", help="Имя пользователя")
    p_login.add_argument("--password", "-p", help="Пароль")

    # tx
    p_tx = subparsers.add_parser("tx", help="Добавить финансовую операцию")
    p_tx.add_argument("--type", dest="tx_type", choices=["INCOME", "EXPENSE"], default="EXPENSE", help="Тип (INCOME/EXPENSE)")
    p_tx.add_argument("--amount", "-a", required=True, help="Сумма в рублях (например: 1500.50)")
    p_tx.add_argument("--account", dest="account_code", default="1010", help="Код счета (1010 - Карта, 1020 - Наличные)")
    p_tx.add_argument("--category", dest="category_code", help="Код категории (5010 - Продукты, 4010 - Зарплата)")
    p_tx.add_argument("--desc", dest="description", help="Описание операции")
    p_tx.add_argument("--personal-for-common", action="store_true", help="Оплата общей покупки с личной карты (без автодолга)")
    p_tx.add_argument("--password", "-p", help="Мастер-пароль для разблокировки")

    # transfer
    p_tr = subparsers.add_parser("transfer", help="Внутренний перевод между счетами")
    p_tr.add_argument("--from", dest="from_code", required=True, help="Код счета списания (например 1010)")
    p_tr.add_argument("--to", dest="to_code", required=True, help="Код счета зачисления (например 1030)")
    p_tr.add_argument("--amount", "-a", required=True, help="Сумма перевода в рублях")
    p_tr.add_argument("--desc", dest="description", help="Описание перевода")
    p_tr.add_argument("--password", "-p", help="Мастер-пароль для разблокировки")

    # create-account
    p_acc = subparsers.add_parser("create-account", help="Создать новый счет")
    p_acc.add_argument("--name", required=True, help="Название счета")
    p_acc.add_argument("--subtype", choices=["DEBIT_CARD", "CASH", "CHECKING", "SAVINGS", "DEPOSIT", "CREDIT_CARD"], default="DEBIT_CARD", help="Тип счета")
    p_acc.add_argument("--scope", choices=["COMMON", "PERSONAL_HUSBAND", "PERSONAL_WIFE"], default="COMMON", help="Принадлежность средств")
    p_acc.add_argument("--code", help="Бухгалтерский код")
    p_acc.add_argument("--initial-balance", default="0", help="Начальный остаток в рублях")
    p_acc.add_argument("--credit-limit", default="0", help="Кредитный лимит в рублях")
    p_acc.add_argument("--description", help="Описание/примечание")
    p_acc.add_argument("--password", "-p", help="Мастер-пароль для разблокировки")

    # overview / balance
    p_ov = subparsers.add_parser("overview", help="Показать сводный баланс и все счета семьи")
    p_ov.add_argument("--password", "-p", help="Мастер-пароль для разблокировки")
    p_bal = subparsers.add_parser("balance", help="Показать сводный баланс и все счета семьи")
    p_bal.add_argument("--password", "-p", help="Мастер-пароль для разблокировки")

    # web
    p_web = subparsers.add_parser("web", help="Запустить локальный веб-сервер")
    p_web.add_argument("--port", type=int, default=8000, help="Порт (по умолчанию 8000)")

    # migrate-to-encrypted
    p_mig = subparsers.add_parser("migrate-to-encrypted", help="Мигрировать открытую БД SQLite в зашифрованный контейнер AES-256-GCM")
    p_mig.add_argument("--password", "-p", help="Мастер-пароль для шифрования")

    # unlock-db
    p_unl = subparsers.add_parser("unlock-db", help="Проверить разблокировку зашифрованного контейнера")
    p_unl.add_argument("--password", "-p", help="Мастер-пароль")

    # change-password
    p_chp = subparsers.add_parser("change-password", help="Сменить мастер-пароль зашифрованного контейнера")
    p_chp.add_argument("--old-password", help="Старый мастер-пароль")
    p_chp.add_argument("--new-password", help="Новый мастер-пароль")

    args = parser.parse_args()

    if args.command == "status":
        cmd_status(args)
    elif args.command == "init":
        cmd_init(args)
    elif args.command == "setup-owner":
        cmd_setup_owner(args)
    elif args.command == "login":
        cmd_login(args)
    elif args.command == "tx":
        cmd_add_transaction(args)
    elif args.command == "transfer":
        cmd_transfer(args)
    elif args.command == "create-account":
        cmd_create_account(args)
    elif args.command in ("balance", "overview"):
        cmd_overview(args)
    elif args.command == "web":
        cmd_web(args)
    elif args.command == "migrate-to-encrypted":
        cmd_migrate_to_encrypted(args)
    elif args.command == "unlock-db":
        cmd_unlock_db(args)
    elif args.command == "change-password":
        cmd_change_password(args)
    else:
        cmd_status(args)


if __name__ == "__main__":
    main()
