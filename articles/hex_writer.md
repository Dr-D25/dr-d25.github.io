# hex_writer.py

Скрипт для записи байтов в файл по заданному смещению (адресу). Позволяет точечно изменять содержимое бинарных файлов, прошивок, образов дисков и т.п., не перезаписывая файл целиком.

```python
#!/usr/bin/env python3

import argparse
import os
import sys

def parse_hex(data: str) -> bytes:


    cleaned = ''.join(data.split())
    if not cleaned:
        raise ValueError("Пустая строка данных")
    if len(cleaned) % 2 != 0:
        raise ValueError("Шестнадцатеричная строка должна содержать чётное количество символов")
    return bytes.fromhex(cleaned)

def main():
    parser = argparse.ArgumentParser(
        description="Записывает байты в файл по заданному смещению (адресу)."
    )
    parser.add_argument("-f", "--file", required=True, help="Путь к целеому файлу")
    parser.add_argument("-a", "--address", required=True, help="Смещение в файле (десятичное или 0xHEX)")
    parser.add_argument("-d", "--data", required=True, help="Данные для записи: шестнадцатеричная строка или текст")
    parser.add_argument("--text", action="store_true", help="Интерпретировать данные как текстовую строку (иначе как hex)")
    parser.add_argument("--expand", action="store_true", help="Расширить файл нулями, если адрес за пределами файла")

    args = parser.parse_args()


    try:
        if args.address.lower().startswith("0x"):
            offset = int(args.address, 16)
        else:
            offset = int(args.address)
    except ValueError:
        print("Ошибка: неверный формат адреса. Используйте десятичное число или 0xHEX")
        sys.exit(1)

    if offset < 0:
        print("Ошибка: смещение не может быть отрицательным")
        sys.exit(1)

    if args.text:
        data = args.data.encode('utf-8')
    else:
        try:
            data = parse_hex(args.data)
        except ValueError as e:
            print(f"Ошибка при разборе hex-данных: {e}")
            sys.exit(1)


    try:
        with open(args.file, "r+b") as f:
            f.seek(0, os.SEEK_END)
            file_size = f.tell()

            if offset + len(data) > file_size:
                if args.expand:

                    f.write(b'\x00' * (offset + len(data) - file_size))
                else:
                    print(f"Предупреждение: запись за пределами файла (размер {file_size}, запись до {offset + len(data)}).")
                    print("Используйте --expand, чтобы автоматически расширить файл.")
                    sys.exit(1)

            f.seek(offset, os.SEEK_SET)
            f.write(data)

        print(f"Успешно записано {len(data)} байт(а) по смещению {hex(offset)} в файл {args.file}")
    except PermissionError:
        print("Ошибка: нет прав на запись в файл")
        sys.exit(1)
    except FileNotFoundError:
        print(f"Ошибка: файл {args.file} не найден")
        sys.exit(1)
    except Exception as e:
        print(f"Неожиданная ошибка: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
```

## Возможности

   - Запись данных по произвольному смещению в файле.

   - Поддержка двух режимов входных данных:

       - hex — шестнадцатеричная строка (по умолчанию);

       - текст — обычная строка в кодировке UTF-8 (флаг --text).

   - Адрес можно указывать как в десятичном виде (1024), так и в шестнадцатеричном (0x400).

   - Опциональное автоматическое расширение файла нулями, если адрес выходит за его текущие границы (--expand).

   - Аккуратная обработка ошибок: неверный адрес, пустые данные, отсутствие файла, недостаток прав, запись за пределами файла.

## Требования

```text
    Python 3.6+

    Только стандартная библиотека (argparse, os, sys).
```

## Использование

```bash

./hexwriter.py -f <файл> -a <адрес> -d <данные> [--text] [--expand]
```

## Аргументы

| Аргумент | Обязателен	| Описание |
|---|---|---|
| -f, --file | да | Путь к целевому файлу. |
| -a, --address | да | Смещение в файле: десятичное (1024) или шестнадцатеричное (0x400). |
| -d, --data | да | Данные для записи: hex-строка или текст. |
| --text | нет | Интерпретировать --data как текстовую строку UTF-8 (иначе — как hex). |
| --expand | нет | Расширить файл нулями, если адрес выходит за его пределы. |

## Примеры

1. Записать 4 байта DE AD BE EF по смещению 0x100:

```bash
./hexwriter.py -f firmware.bin -a 0x100 -d "DE AD BE EF"
```
2. Записать текстовую строку Hello по смещению 512 (десятичное):

```bash
./hexwriter.py -f data.bin -a 512 -d "Hello" --text
```

3. Записать данные за пределами файла, автоматически расширив его нулями:

```bash

./hexwriter.py -f image.img -a 0x10000 -d "CAFEBABE" --expand
```

## Поведение и ограничения

   - Если --data содержит нечётное количество hex-символов или недопустимые символы — выводится ошибка и скрипт завершается с кодом 1.

   - При записи за пределы файла без --expand выводится предупреждение и скрипт завершается с кодом 1.

   - Отрицательное смещение запрещено.

   - Файл открывается в режиме r+b, то есть должен существовать. Новые файлы скрипт не создаёт.

   - Пробелы и переводы строк в hex-строке игнорируются (удобно для многострочного ввода).

## Коды возврата

| Код | Причина |
|---|---|
| 0	| Успешная запись. |
| 1	| Ошибка разбора адреса/данных, запись за пределы файла без --expand, отсутствие файла или прав, прочие ошибки.|

### Пример вывода

```text

Успешно записано 4 байт(а) по смещению 0x100 в файл firmware.bin
```
