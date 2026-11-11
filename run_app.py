#!/usr/bin/env python3
"""
Family Finances OS - Главный исполняемый скрипт запуска системы.

Использование:
    python run_app.py              # Локальный запуск на 127.0.0.1:8000 с автооткрытием браузера
    python run_app.py --lan        # Доступ со смартфонов семьи в домашней сети Wi-Fi (0.0.0.0:8000)
    python run_app.py --port 8080  # Выбор альтернативного порта
"""
import argparse
import ipaddress
import json
import os
import socket
import subprocess
import sys
import threading
import time
import webbrowser
from pathlib import Path

# Обеспечиваем доступность пакета family_finances_os в sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def get_local_ip() -> str:
    """Определяет IP-адрес текущего компьютера в домашней сети Wi-Fi."""
    if sys.platform == "win32":
        try:
            # Prefer a physical LAN adapter over a VPN default route.
            query = "Get-NetIPConfiguration | Where-Object { $_.NetAdapter.HardwareInterface -and $_.NetAdapter.Status -eq 'Up' -and $_.IPv4DefaultGateway } | ForEach-Object { $_.IPv4Address.IPAddress } | ConvertTo-Json -Compress"
            result = subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", query],
                capture_output=True, text=True, timeout=8,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            addresses = json.loads(result.stdout) if result.returncode == 0 and result.stdout.strip() else []
            if isinstance(addresses, str):
                addresses = [addresses]
            for address in addresses:
                ip = ipaddress.ip_address(address)
                if ip.version == 4 and ip.is_private and not ip.is_loopback and not ip.is_link_local:
                    return str(ip)
        except (ValueError, OSError, subprocess.TimeoutExpired):
            pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        # Подключение к недостижимому IP для определения исходящего интерфейса
        s.connect(("10.255.255.255", 1))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "127.0.0.1"


def open_browser_delayed(url: str, delay: float = 1.0):
    """Открывает браузер по умолчанию с небольшой задержкой для готовности сокета."""
    def _worker():
        time.sleep(delay)
        try:
            webbrowser.open(url)
        except Exception:
            pass
    t = threading.Thread(target=_worker, daemon=True)
    t.start()


def print_banner(host: str, port: int, local_ip: str):
    print("=" * 68)
    print("      FAMILY FINANCES OS  v0.2.0-release")
    print("      Закрытая автономная система управления финансами семьи")
    print("=" * 68)
    print(f"[*] Локальный веб-интерфейс:   http://127.0.0.1:{port}")
    if host in ("0.0.0.0", "::"):
        print(f"[*] Адрес для телефона:       http://{local_ip}:{port}")
        print("[*] Телефон и компьютер должны быть в одной домашней сети Wi-Fi.")
    else:
        print("[*] Для доступа с телефона запустите start_lan.bat.")
    print("[*] Безопасность хранилища:    Envelope Encryption (AES-256-GCM + PBKDF2 600k)")
    print("[*] База данных:               Локально на диске (SQLite)")
    print("[*] Для остановки сервера нажмите Ctrl + C")
    print("=" * 68)
    print()


def main():
    default_host = os.environ.get("FFOS_HOST", "127.0.0.1")
    default_port = int(os.environ.get("FFOS_PORT", "8000"))
    env_no_browser = os.environ.get("FFOS_NO_BROWSER", "0").lower() in ("1", "true", "yes")

    parser = argparse.ArgumentParser(description="Family Finances OS Runner")
    parser.add_argument("--port", type=int, default=default_port, help=f"Порт веб-сервера (по умолчанию {default_port})")
    parser.add_argument("--host", type=str, default=default_host, help=f"Хост привязки (по умолчанию {default_host})")
    parser.add_argument("--lan", action="store_true", help="Разрешить доступ со смартфонов семьи в сети Wi-Fi (0.0.0.0)")
    parser.add_argument("--no-browser", action="store_true", default=env_no_browser, help="Не открывать браузер автоматически при старте")
    args = parser.parse_args()

    host = "0.0.0.0" if args.lan else args.host
    port = args.port
    local_ip = get_local_ip()

    print_banner(host, port, local_ip)

    if not args.no_browser:
        open_browser_delayed(f"http://127.0.0.1:{port}")

    from family_finances_os.web_server import start_server
    try:
        start_server(port=port, host=host)
    except Exception as e:
        print(f"[Family Finances OS] Ошибка запуска сервера: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
