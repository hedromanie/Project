import os
import subprocess
import sys

def main():
    print("Компилятор Python-скриптов в EXE")
    
    script_name = input("Введите имя Python-скрипта (без .py): ").strip()
    if not script_name:
        print("Ошибка: не указано имя скрипта!")
        return
    
    if not os.path.exists(script_name + ".py"):
        print(f"Ошибка: файл '{script_name}.py' не найден!")
        return

    print("Выберите тип приложения:")
    print("1 - Консольное приложение (по умолчанию)")
    print("2 - GUI приложение (без консоли)")
    app_type = input("Введите номер [1-2]: ").strip()

    console = "--console"
    if app_type == "2":
        console = "--noconsole"

    try:
        subprocess.run([
            sys.executable, "-m", "PyInstaller",
            console,
            "--onefile",
            "--clean",
            "--icon=other/images.ico",
            f"{script_name}.py"
        ], check=True)
        
        print(f"\nКомпиляция успешно завершена!")
        print(f"Собранный файл: dist\\{script_name}.exe")
        
    except subprocess.CalledProcessError:
        print("\nОшибка компиляции! Проверьте:")
        print("1. Установлен ли PyInstaller (pip install pyinstaller)")
        print("2. Нет ли ошибок в исходном коде")
    except Exception as e:
        print(f"\nНеизвестная ошибка: {str(e)}")

if __name__ == "__main__":
    main()
    input("\nНажмите Enter для выхода...")