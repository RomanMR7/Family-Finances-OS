@echo off
chcp 65001 >nul
title Family Finances OS
cd /d "%~dp0"

echo ================================================================
echo        Запуск Family Finances OS (Семейная финансовая система)
echo ================================================================
echo.

set PYTHON_CMD=

if exist "%USERPROFILE%\.local\bin\python3.12.exe" (
    set "PATH=%USERPROFILE%\.local\bin;%PATH%"
    set PYTHON_CMD="%USERPROFILE%\.local\bin\python3.12.exe"
    goto run
)

if exist "%USERPROFILE%\.local\bin\python3.11.exe" (
    set "PATH=%USERPROFILE%\.local\bin;%PATH%"
    set PYTHON_CMD="%USERPROFILE%\.local\bin\python3.11.exe"
    goto run
)

where python3.12.exe >nul 2>&1
if %ERRORLEVEL% equ 0 (
    set PYTHON_CMD=python3.12.exe
    goto run
)

where python.exe >nul 2>&1
if %ERRORLEVEL% equ 0 (
    set PYTHON_CMD=python.exe
    goto run
)

where py.exe >nul 2>&1
if %ERRORLEVEL% equ 0 (
    set PYTHON_CMD=py.exe -3
    goto run
)

if exist "%USERPROFILE%\AppData\Roaming\uv\python\cpython-3.12-windows-x86_64-none\python.exe" (
    set PYTHON_CMD="%USERPROFILE%\AppData\Roaming\uv\python\cpython-3.12-windows-x86_64-none\python.exe"
    goto run
)

echo [ОШИБКА] Интерпретатор Python не найден в системе.
echo Пожалуйста, установите Python 3.10+ с официального сайта https://python.org
echo или через winget: winget install Python.Python.3.12
pause
exit /b 1

:run
echo [*] Запуск через: %PYTHON_CMD%
%PYTHON_CMD% run_app.py %*
if %ERRORLEVEL% neq 0 (
    echo.
    echo [ВНИМАНИЕ] Приложение завершилось с кодом ошибки %ERRORLEVEL%.
    pause
)
