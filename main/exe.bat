@echo off
chcp 65001
title Сборка

echo 🔨 Запускаем сборку...
python build.py build
if errorlevel 1 (
    echo ❌ Ошибка сборки с cx_Freeze!
    echo Попробуйте другой способ сборки.
    pause
    exit /b 1
)

echo.
echo ✅ Сборка завершена успешно!
echo 📁 EXE файл: build\CiscoNetworkTool1.exe
goto success