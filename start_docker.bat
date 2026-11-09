@echo off
chcp 65001 >nul
title Family Finances OS (Docker)
cd /d "%~dp0"

echo ================================================================
echo        Запуск Family Finances OS в Docker контейнере
echo ================================================================
echo.

where docker >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ОШИБКА] Docker CLI не найден в системе.
    echo Убедитесь, что Docker Desktop установлен и запущен.
    pause
    exit /b 1
)

echo [*] Сборка и запуск контейнера family_finances_os...
docker compose -p family-finances-os up -d --build

if %ERRORLEVEL% equ 0 (
    echo.
    echo [УСПЕХ] Контейнер успешно запущен в фоновом режиме!
    echo [*] Локальный адрес:   http://127.0.0.1:8000
    echo [*] Просмотр логов:    docker compose logs -f
    echo [*] Остановка службы:  docker compose down
    echo.
    timeout /t 2 >nul
    start http://127.0.0.1:8000
) else (
    echo.
    echo [ОШИБКА] Не удалось запустить Docker контейнер.
    pause
)
