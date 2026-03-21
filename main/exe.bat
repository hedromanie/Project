@echo off
chcp 65001
title Сборка

echo 🔨 Запускаем сборку...
python build.py build

echo.
echo ✅ Сборка завершена успешно!
goto success
