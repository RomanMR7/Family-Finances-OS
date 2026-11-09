#!/usr/bin/env bash
# Family Finances OS - Docker Start Script for Linux/macOS
set -e

echo "================================================================"
echo "       Запуск Family Finances OS в Docker контейнере"
echo "================================================================"

if ! command -v docker &> /dev/null; then
    echo "[ОШИБКА] Docker не найден в PATH."
    exit 1
fi

echo "[*] Сборка и запуск контейнера..."
docker compose -p family-finances-os up -d --build

echo ""
echo "[УСПЕХ] Контейнер запущен!"
echo "[*] Веб-интерфейс: http://127.0.0.1:8000"
echo "[*] Просмотр логов: docker compose logs -f"
