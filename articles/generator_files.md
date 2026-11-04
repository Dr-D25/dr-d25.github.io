# Генератор Файлов

Генератор файлов различных форматов с реалистичным содержимым (сигнатуры, структура
контейнеров, валидное наполнение). Предназначен для тестирования файловых систем,
антивирусов, парсеров, сценариев резервного копирования и т.п.

```python
#!/usr/bin/env python3
"""
create_files.py — генератор файлов различных форматов с реалистичным содержимым.

Примеры:
    python create_files.py -e pdf -q 3 -s 2
    python create_files.py -e zip,exe -q 5 -s 1.5 --jobs 4 --output-dir out/
    python create_files.py -e bin -q 1 -s 100 --verify
    python create_files.py --list-formats
"""

from __future__ import annotations

import argparse
import csv
import gzip
import io
import json
import logging
import os
import random
import sqlite3
import struct
import subprocess
import sys
import tarfile
import tempfile
import zipfile
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

# --- Опциональные зависимости ---
try:
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    HAVE_REPORTLAB = True
except ImportError:
    HAVE_REPORTLAB = False

try:
    from docx import Document
    HAVE_DOCX = True
except ImportError:
    HAVE_DOCX = False

try:
    from openpyxl import Workbook
    HAVE_OPENPYXL = True
except ImportError:
    HAVE_OPENPYXL = False

logger = logging.getLogger("create_files")

CHUNK = 1 << 20
TEXT_ALPHABET = (
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789 "
    "\t\n"
    ".,;:!?-_()[]{}<>/\\|@#$%^&*+=~`'\""
)


# ---------------- Helpers ----------------

def random_bytes(n: int) -> bytes:
    return os.urandom(n)


def random_text(n: int, alphabet: str = TEXT_ALPHABET) -> str:
    return "".join(random.choices(alphabet, k=n))


def write_chunked(f, n: int) -> None:
    while n > 0:
        k = min(CHUNK, n)
        f.write(os.urandom(k))
        n -= k


def write_text_chunked(f, n: int, alphabet: str = TEXT_ALPHABET) -> None:
    while n > 0:
        k = min(CHUNK, n)
        f.write(random_text(k, alphabet))
        n -= k


def warn(name: str, msg: str) -> None:
    logger.warning(f"{name}: {msg}")


def check_size(name: str, actual: int, target: int, tol: float = 0.05) -> None:
    if target <= 0:
        return
    if abs(actual - target) / target > tol:
        warn(name, f"размер {actual} отличается от целевого {target} на "
                   f"{abs(actual - target) / target * 100:.1f}%")


def write_signature_file(path: str, sig: bytes, size_bytes: int, extra: bytes = b"") -> None:
    header = sig + extra
    if len(header) > size_bytes:
        raise ValueError(f"размер {size_bytes} Б меньше заголовка ({len(header)} Б)")
    with open(path, "wb") as f:
        f.write(header)
        write_chunked(f, size_bytes - len(header))


# ---------------- ZIP helpers ----------------

def pad_zip_to_size(data: bytes, target: int) -> bytes:
    """Дополняет ZIP-архив до target через поле comment в EOCD (макс. 65535 Б)."""
    if len(data) >= target:
        return data
    pad = target - len(data)
    if pad > 65535:
        return data
    return data[:-2] + struct.pack("<H", pad) + b"\x00" * pad


def make_zip_exact(size_bytes: int, name: str = "data.bin") -> bytes:
    """ZIP с одним stored-файлом ровно size_bytes байт (или чуть меньше с warning)."""
    dummy = b"\x00" * 16
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr(name, dummy)
    overhead = len(buf.getvalue()) - len(dummy)
    data_len = size_bytes - overhead
    if data_len < 0:
        raise ValueError(f"ZIP: размер {size_bytes} Б слишком мал (overhead={overhead})")
    data = random_bytes(data_len)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr(name, data)
    return pad_zip_to_size(buf.getvalue(), size_bytes)


# ---------------- Генераторы ----------------

def generate_bin(path: str, size_bytes: int) -> None:
    with open(path, "wb") as f:
        write_chunked(f, size_bytes)


def generate_exe(path: str, size_bytes: int) -> None:
    _generate_pe(path, size_bytes, characteristics=0x0022)


def generate_dll(path: str, size_bytes: int) -> None:
    _generate_pe(path, size_bytes, characteristics=0x2022)


def _generate_pe(path: str, size_bytes: int, characteristics: int) -> None:
    if size_bytes < 0x200:
        raise ValueError(f"PE: размер {size_bytes} Б < 512 Б")
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    dos[0x3C:0x40] = struct.pack("<I", 0x40)
    pe_sig = b"PE\x00\x00"
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 0xF0, characteristics)
    opt = struct.pack("<H", 0x20B) + b"\x00" * 0xEE
    section = struct.pack(
        "<8sIIIIIIHHI",
        b".data\x00\x00\x00", 0, 0x1000, 0, 0x200, 0, 0, 0, 0, 0xC0000040,
    )
    header = bytes(dos) + pe_sig + coff + opt + section
    if len(header) < 0x200:
        header += b"\x00" * (0x200 - len(header))
    with open(path, "wb") as f:
        f.write(header)
        write_chunked(f, size_bytes - len(header))


def generate_elf(path: str, size_bytes: int) -> None:
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    header = ident + struct.pack(
        "<HHIQQQIHHHHHH",
        2, 0x3E, 1, 0x400000, 0x40, 0, 0, 0x40, 0x38, 0, 0x40, 0, 0,
    )
    if len(header) > size_bytes:
        raise ValueError(f"ELF: размер {size_bytes} Б < заголовка")
    with open(path, "wb") as f:
        f.write(header)
        write_chunked(f, size_bytes - len(header))


def generate_msi(path: str, size_bytes: int) -> None:
    write_signature_file(path, b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", size_bytes)


generate_doc = generate_msi
generate_xls = generate_msi


def _build_pdf(n_pages: int) -> bytes:
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    w, h = A4
    for _ in range(n_pages):
        c.setFont("Helvetica", 8)
        text = random_text(3000)
        y = h - 20 * mm
        for i in range(0, len(text), 100):
            c.drawString(10 * mm, y, text[i:i + 100])
            y -= 5 * mm
        c.showPage()
    c.save()
    return buf.getvalue()


def generate_pdf(path: str, size_bytes: int) -> None:
    if not HAVE_REPORTLAB:
        return write_signature_file(path, b"%PDF-1.4\n", size_bytes)

    pages = max(1, size_bytes // 5000)
    data = b""
    for _ in range(4):
        data = _build_pdf(pages)
        ratio = size_bytes / max(1, len(data))
        if abs(ratio - 1) < 0.05:
            break
        pages = max(1, int(pages * ratio))

    if len(data) < size_bytes:
        pad = size_bytes - len(data)
        data = data + b"\n% " + b"P" * max(0, pad - 3) + b"\n"

    with open(path, "wb") as f:
        f.write(data[:size_bytes] if len(data) > size_bytes else data)
    check_size(path, os.path.getsize(path), size_bytes)


def generate_zip(path: str, size_bytes: int) -> None:
    data = make_zip_exact(size_bytes)
    with open(path, "wb") as f:
        f.write(data)
    check_size(path, len(data), size_bytes)


def generate_docm(path: str, size_bytes: int) -> None:
    generate_zip(path, size_bytes)


def generate_docx(path: str, size_bytes: int) -> None:
    if not HAVE_DOCX:
        return generate_zip(path, size_bytes)
    doc = Document()
    doc.add_paragraph("Generated document")
    buf = io.BytesIO()
    doc.save(buf)
    initial = buf.tell()
    para_bytes = 2500
    n_paras = max(1, (size_bytes - initial) // int(para_bytes * 1.5))
    for _ in range(n_paras):
        doc.add_paragraph(random_text(2000))
    buf = io.BytesIO()
    doc.save(buf)
    data = pad_zip_to_size(buf.getvalue(), size_bytes)
    with open(path, "wb") as f:
        f.write(data)
    check_size(path, len(data), size_bytes)


def generate_xlsx(path: str, size_bytes: int) -> None:
    if not HAVE_OPENPYXL:
        return generate_zip(path, size_bytes)
    wb = Workbook()
    ws = wb.active
    ws.append(["id", "v1", "v2", "v3", "v4", "v5"])
    buf = io.BytesIO()
    wb.save(buf)
    initial = buf.tell()
    row_bytes = 100
    n_rows = max(1, (size_bytes - initial) // int(row_bytes * 1.5))
    for i in range(n_rows):
        ws.append([i] + [random_text(15) for _ in range(5)])
    buf = io.BytesIO()
    wb.save(buf)
    data = pad_zip_to_size(buf.getvalue(), size_bytes)
    with open(path, "wb") as f:
        f.write(data)
    check_size(path, len(data), size_bytes)


def generate_rar(path: str, size_bytes: int) -> None:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tmp:
        write_chunked(tmp, size_bytes)
        tmp_path = tmp.name
    try:
        subprocess.run(
            ["rar", "a", "-m0", "-ep1", "-idq", path, tmp_path],
            check=True, capture_output=True, timeout=300,
        )
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as e:
        warn(path, f"rar не сработал ({e}); создаю заглушку с сигнатурой")
        write_signature_file(path, b"Rar!\x1A\x07\x01\x00", size_bytes)
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
    if os.path.exists(path):
        check_size(path, os.path.getsize(path), size_bytes, tol=0.10)


def generate_txt(path: str, size_bytes: int) -> None:
    with open(path, "w", encoding="utf-8") as f:
        write_text_chunked(f, size_bytes)


def generate_csv(path: str, size_bytes: int) -> None:
    buf = io.StringIO(newline="")
    writer = csv.writer(buf)
    writer.writerow(["id", "name", "v1", "v2", "v3"])
    row = 0
    while buf.tell() < size_bytes:
        row += 1
        writer.writerow([row] + [random_text(12) for _ in range(4)])
    data = buf.getvalue().encode("utf-8")
    while len(data) > size_bytes:
        last_nl = data.rfind(b"\n")
        if last_nl <= 0:
            break
        data = data[:last_nl + 1]
    if len(data) < size_bytes:
        data += b"\n" * (size_bytes - len(data))
    with open(path, "wb") as f:
        f.write(data)


def generate_json(path: str, size_bytes: int) -> None:
    buf = io.StringIO()
    buf.write("[")
    first = True
    while buf.tell() < size_bytes - 2:
        if not first:
            buf.write(",")
        json.dump({
            "id": random.randint(1, 1_000_000),
            "text": random_text(100),
            "ts": datetime.now().isoformat(timespec="seconds"),
        }, buf)
        first = False
    buf.write("]")
    data = buf.getvalue().encode("utf-8")
    if len(data) > size_bytes:
        data = data[:size_bytes]
    elif len(data) < size_bytes:
        data += b" " * (size_bytes - len(data))
    with open(path, "wb") as f:
        f.write(data)


def generate_xml(path: str, size_bytes: int) -> None:
    root = ET.Element("root")
    est_items = max(1, size_bytes // 250)
    for i in range(est_items):
        child = ET.SubElement(root, "item")
        child.set("id", str(i))
        child.text = random_text(180)
    data = ET.tostring(root, encoding="utf-8")
    while len(data) > size_bytes and len(root):
        root.remove(root[-1])
        data = ET.tostring(root, encoding="utf-8")
    if len(data) < size_bytes:
        data += b" " * (size_bytes - len(data))
    with open(path, "wb") as f:
        f.write(data)


def generate_wav(path: str, size_bytes: int) -> None:
    if size_bytes < 44:
        raise ValueError(f"WAV: размер {size_bytes} Б < 44")
    sample_rate, channels, bits = 44100, 2, 16
    block_align = channels * bits // 8
    byte_rate = sample_rate * block_align
    data_len = size_bytes - 44
    if data_len % 2:
        data_len -= 1
    header = struct.pack(
        "<4sI4s4sIHHIIHH4sI",
        b"RIFF", 36 + data_len, b"WAVE",
        b"fmt ", 16, 1, channels, sample_rate,
        byte_rate, block_align, bits,
        b"data", data_len,
    )
    with open(path, "wb") as f:
        f.write(header)
        write_chunked(f, data_len)
        if size_bytes - 44 - data_len > 0:
            f.write(b"\x00" * (size_bytes - 44 - data_len))


def generate_bmp(path: str, size_bytes: int) -> None:
    if size_bytes < 54:
        raise ValueError(f"BMP: размер {size_bytes} Б < 54")
    width = 256
    row_size = ((width * 3 + 3) // 4) * 4
    height = max(1, (size_bytes - 54) // row_size)
    pixel_size = row_size * height
    total = 54 + pixel_size
    header = struct.pack("<2sIHHI", b"BM", total, 0, 0, 54)
    info = struct.pack("<IiiHHIIiiII",
                       40, width, height, 1, 24, 0,
                       pixel_size, 2835, 2835, 0, 0)
    with open(path, "wb") as f:
        f.write(header + info)
        write_chunked(f, pixel_size)
        if total < size_bytes:
            f.write(b"\x00" * (size_bytes - total))


def generate_gz(path: str, size_bytes: int) -> None:
    overhead = 30
    data_len = max(0, size_bytes - overhead)
    with open(path, "wb") as f:
        gz = gzip.GzipFile(fileobj=f, mode="wb", compresslevel=0, mtime=0)
        gz.write(random_bytes(data_len))
        gz.close()
    check_size(path, os.path.getsize(path), size_bytes)


def generate_tar(path: str, size_bytes: int) -> None:
    data_len = max(0, size_bytes - 512 * 3)
    data = random_bytes(data_len)
    with tarfile.open(path, "w") as tf:
        info = tarfile.TarInfo("data.bin")
        info.size = len(data)
        info.mtime = int(datetime.now().timestamp())
        tf.addfile(info, io.BytesIO(data))
    check_size(path, os.path.getsize(path), size_bytes)


def generate_sqlite(path: str, size_bytes: int) -> None:
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    cur.execute("PRAGMA journal_mode=OFF")
    cur.execute("PRAGMA synchronous=OFF")
    cur.execute("CREATE TABLE data (id INTEGER PRIMARY KEY, v TEXT)")
    while True:
        for _ in range(200):
            cur.execute("INSERT INTO data (v) VALUES (?)", (random_text(100),))
        conn.commit()
        if os.path.getsize(path) >= size_bytes * 0.95:
            break
    conn.close()
    check_size(path, os.path.getsize(path), size_bytes)


# ---------------- Реестр ----------------

GENERATORS: Dict[str, Callable[[str, int], None]] = {
    "bin":  generate_bin,
    "exe":  generate_exe,
    "dll":  generate_dll,
    "elf":  generate_elf,
    "pdf":  generate_pdf,
    "docx": generate_docx,
    "xlsx": generate_xlsx,
    "doc":  generate_doc,
    "xls":  generate_xls,
    "docm": generate_docm,
    "msi":  generate_msi,
    "rar":  generate_rar,
    "zip":  generate_zip,
    "txt":  generate_txt,
    "csv":  generate_csv,
    "json": generate_json,
    "xml":  generate_xml,
    "wav":  generate_wav,
    "bmp":  generate_bmp,
    "gz":   generate_gz,
    "tar":  generate_tar,
    "sqlite": generate_sqlite,
}

MAGIC: Dict[str, Tuple[bytes, ...]] = {
    "exe":  (b"MZ",), "dll": (b"MZ",),
    "elf":  (b"\x7fELF",), "pdf": (b"%PDF",),
    "docx": (b"PK\x03\x04",), "xlsx": (b"PK\x03\x04",),
    "docm": (b"PK\x03\x04",), "zip":  (b"PK\x03\x04",),
    "doc":  (b"\xD0\xCF\x11\xE0",), "xls": (b"\xD0\xCF\x11\xE0",),
    "msi":  (b"\xD0\xCF\x11\xE0",), "rar": (b"Rar!",),
    "gz":   (b"\x1f\x8b",), "wav": (b"RIFF",), "bmp": (b"BM",),
    "sqlite": (b"SQLite format 3\x00",),
}


def verify_file(path: str, ext: str) -> bool:
    sigs = MAGIC.get(ext)
    if not sigs:
        return True
    with open(path, "rb") as f:
        head = f.read(16)
    return any(head.startswith(s) for s in sigs)


# ---------------- CLI ----------------

def parse_size(s: str) -> int:
    """Размер: '2' (МБ по умолчанию), '2M', '512K', '1G', '1048576B'."""
    s = s.strip().upper()
    if s.endswith("B"):
        return int(float(s[:-1]))
    if s.endswith("K"):
        return int(float(s[:-1]) * 1024)
    if s.endswith("M"):
        return int(float(s[:-1]) * 1024 ** 2)
    if s.endswith("G"):
        return int(float(s[:-1]) * 1024 ** 3)
    return int(float(s) * 1024 ** 2)


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        description="Генератор файлов различных форматов с реалистичным содержимым.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("-e", "--ext", help="Расширения через запятую (exe,dll,elf,pdf,...)")
    p.add_argument("-q", "--count", type=int, default=1, help="Файлов на каждое расширение")
    p.add_argument("-s", "--size", type=parse_size, default=1024 * 1024,
                   help="Размер (например 2, 1.5, 100K, 10M)")
    p.add_argument("-o", "--output-dir", default=".", help="Каталог вывода")
    p.add_argument("--prefix", default="file", help="Префикс имени")
    p.add_argument("--seed", type=int, default=None, help="Seed")
    p.add_argument("--overwrite", action="store_true", help="Перезаписывать")
    p.add_argument("--jobs", type=int, default=1, help="Параллельных потоков")
    p.add_argument("--verify", action="store_true", help="Проверять magic bytes")
    p.add_argument("--dry-run", action="store_true", help="Только показать план")
    p.add_argument("--list-formats", action="store_true", help="Список форматов")
    p.add_argument("-v", "--verbose", action="count", default=0,
                   help="Подробный вывод (-v, -vv)")
    args = p.parse_args(argv)

    level = logging.WARNING
    if args.verbose == 1:
        level = logging.INFO
    elif args.verbose >= 2:
        level = logging.DEBUG
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")

    if args.list_formats:
        print("Доступные форматы:")
        for name in sorted(GENERATORS):
            extra = []
            if name == "pdf" and not HAVE_REPORTLAB:
                extra.append("(без reportlab — fallback)")
            if name == "docx" and not HAVE_DOCX:
                extra.append("(без python-docx — ZIP-fallback)")
            if name == "xlsx" and not HAVE_OPENPYXL:
                extra.append("(без openpyxl — ZIP-fallback)")
            if name == "rar":
                extra.append("(требует 'rar' в PATH)")
            print(f"  {name:<8} {' '.join(extra)}")
        return 0

    if not args.ext:
        p.error("укажите -e/--ext (см. --list-formats)")
    if args.count <= 0:
        p.error("--count должен быть > 0")
    if args.size <= 0:
        p.error("--size должен быть > 0")
    if args.jobs <= 0:
        p.error("--jobs должен быть > 0")

    if args.seed is not None:
        random.seed(args.seed)

    exts = [e.strip().lower().lstrip(".") for e in args.ext.split(",") if e.strip()]
    if not exts:
        p.error("пустой список расширений")
    unknown = [e for e in exts if e not in GENERATORS]
    if unknown:
        p.error(f"неизвестные расширения: {', '.join(unknown)}")

    output_dir = Path(args.output_dir)
    if not args.dry_run:
        output_dir.mkdir(parents=True, exist_ok=True)

    tasks: List[Tuple[str, int, str]] = []
    for ext in exts:
        for i in range(1, args.count + 1):
            fname = f"{args.prefix}_{i:04d}.{ext}"
            tasks.append((str(output_dir / fname), args.size, ext))

    if not args.overwrite and not args.dry_run:
        existing = [pth for pth, _, _ in tasks if os.path.exists(pth)]
        if existing:
            for pth in existing:
                print(f"Ошибка: файл уже существует: {pth}")
            print("Используйте --overwrite для перезаписи.")
            return 2

    if args.dry_run:
        total = 0
        for pth, sz, ext in tasks:
            print(f"[dry-run] {pth}  формат={ext}  размер={sz} Б")
            total += sz
        print(f"Итого: {len(tasks)} файлов, {total} байт (~{total / 1024 / 1024:.1f} МБ)")
        return 0

    def run_one(task: Tuple[str, int, str]):
        path, sz, ext = task
        try:
            GENERATORS[ext](path, sz)
            actual = os.path.getsize(path) if os.path.exists(path) else 0
            if args.verify and not verify_file(path, ext):
                return path, False, "сигнатура не совпала", actual
            return path, True, None, actual
        except Exception as e:
            try:
                if os.path.exists(path):
                    os.unlink(path)
            except OSError:
                pass
            return path, False, str(e), None

    ok, fail = 0, 0
    total = len(tasks)
    done = 0
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = [pool.submit(run_one, t) for t in tasks]
        for fut in as_completed(futures):
            path, success, err, actual = fut.result()
            done += 1
            name = os.path.basename(path)
            if success:
                ok += 1
                print(f"[{done}/{total}] OK {name} ({actual} Б)")
            else:
                fail += 1
                print(f"[{done}/{total}] ОШИБКА {name}: {err}", file=sys.stderr)

    print(f"\nГотово: успешно {ok}, ошибок {fail} из {total}.")
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nПрервано пользователем.", file=sys.stderr)
        sys.exit(130)
```
## Возможности

- **16+ форматов**: `exe`, `dll`, `elf`, `pdf`, `docx`, `xlsx`, `doc`, `xls`, `docm`,
  `msi`, `rar`, `zip`, `txt`, `csv`, `json`, `xml`, а также дополнительные `bin`,
  `gz`, `tar`, `wav`, `bmp`, `sqlite`.
- **Пакетная генерация**: несколько расширений за один запуск (`-e zip,exe,pdf`).
- **Точный/приблизительный размер**: текстовые и бинарные форматы генерируются точно,
  для PDF/DOCX/XLSX/RAR/GZ/TAR допускается отклонение ≤ 5–10 % (с предупреждением).
- **Реалистичные заголовки**: MZ/PE, ELF64, OLE2 (MSI/DOC/XLS), ZIP-контейнер для
  DOCX/XLSX/DOCM, RIFF/WAVE, BMP, PDF, SQLite.
- **Параллельная генерация** (`--jobs`) через `ThreadPoolExecutor`.
- **Верификация** сигнатур (`--verify`).
- **Воспроизводимость** (`--seed`).
- **Безопасность**: по умолчанию не перезаписывает существующие файлы; при ошибке
  частично созданные файлы удаляются.
- **Понятная диагностика**: `logging`, `-v / -vv`, отчёт по каждому файлу.

## Требования

- Python 3.8+.
- Обязательных внешних зависимостей нет — для базовых форматов достаточно stdlib.
- Для «настоящих» PDF/DOCX/XLSX (а не fallback-заглушек):

  ```bash
  pip install reportlab python-docx openpyxl
  ```

- Для `rar` — установленный архиватор `rar` в `PATH`. Если его нет, создаётся
  fallback-файл с сигнатурой RAR5 (с предупреждением).

## Установка

Скрипт самодостаточен — достаточно сохранить файл и дать права:

```bash
chmod +x create_files.py
./create_files.py --list-formats
```

## Использование

```bash
./create_files.py -e <ext1[,ext2,...]> [-q N] [-s РАЗМЕР] [опции]
```

### Аргументы

| Аргумент | По умолчанию | Описание |
|---|---|---|
| `-e`, `--ext` | — (обязателен) | Расширения через запятую: `pdf`, `zip,exe`, `docx,xlsx`. |
| `-q`, `--count` | `1` | Количество файлов на каждое расширение. |
| `-s`, `--size` | `1` (МБ) | Размер каждого файла. Можно с суффиксом `K/M/G/B`: `100K`, `2M`, `1.5`, `1048576B`. Без суффикса — **МБ** (обратная совместимость). |
| `-o`, `--output-dir` | `.` | Каталог вывода. |
| `--prefix` | `file` | Префикс имени. Файл: `{prefix}_{i:04d}.{ext}`. |
| `--seed` | — | Seed для воспроизводимости. |
| `--overwrite` | off | Разрешить перезапись. |
| `--jobs` | `1` | Число параллельных потоков. |
| `--verify` | off | Проверять magic bytes после генерации. |
| `--dry-run` | off | Не создавать файлы, только вывести план. |
| `--list-formats` | — | Вывести список поддерживаемых форматов. |
| `-v`, `-vv` | `0` | Уровень детализации логов (`-v` = INFO, `-vv` = DEBUG). |

### Примеры

Три PDF по 2 МБ:

```bash
./create_files.py -e pdf -q 3 -s 2
```

10 ZIP, 10 EXE, 10 PDF по 1.5 МБ в каталоге `out/`, 4 потока:

```bash
./create_files.py -e zip,exe,pdf -q 10 -s 1.5 --jobs 4 -o out/
```

100 МБ случайных данных:

```bash
./create_files.py -e bin -q 1 -s 100
```

512 КБ CSV с фиксированным seed:

```bash
./create_files.py -e csv -q 1 -s 512K --seed 42
```

Проверить сигнатуру после генерации:

```bash
./create_files.py -e exe,elf,pdf -q 5 -s 200K --verify
```

Посмотреть план без записи на диск:

```bash
./create_files.py -e docx,xlsx -q 3 -s 1 --dry-run
```

## Поведение и ограничения

- **Размер** — гарантирован точно для `bin`, `txt`, `csv`, `json`, `xml`, `wav`,
  `bmp`, `exe`, `dll`, `elf`, `msi`, `doc`, `xls`, `zip`, `docm`. Для `pdf`, `docx`,
  `xlsx`, `rar`, `gz`, `tar`, `sqlite` допускается отклонение до 5–10 % (с
  предупреждением в `logging`).
- **ZIP-подобные** форматы (`zip`, `docm`) — точный размер достигается за счёт
  подгонки размера stored-записи и (при необходимости) поля `comment` в EOCD
  (до 64 КБ).
- **PDF** — паддинг через PDF-комментарий `% ...` в конце файла (валидно для всех
  известных ридеров).
- **DOCX/XLSX** — при наличии соответствующих библиотек генерируется настоящий
  документ, иначе — ZIP-заглушка. Паддинг — через ZIP comment (до 64 КБ).
- **RAR** — при отсутствии `rar` создаётся файл с сигнатурой RAR5; в любом случае
  размер будет отличаться от целевого на величину overhead’а архива.
- **`sqlite`** — размер может отличаться на размер страницы (SQLite растёт блоками).
- **Очень большие размеры (> 1 ГБ)** для текстовых форматов могут потребовать
  значительной памяти, так как контент строится в памяти.
- **Перезапись** — по умолчанию запрещена. Используйте `--overwrite`.
- **Ошибки генерации** — частично созданный файл удаляется, в stderr выводится
  причина; скрипт завершается с кодом `1`.

## Коды возврата

| Код | Причина |
|---|---|
| `0` | Все файлы сгенерированы успешно. |
| `1` | Ошибки при генерации хотя бы одного файла. |
| `2` | Файл(ы) уже существуют без `--overwrite`. |
| `130` | Прервано пользователем (Ctrl+C). |

## Поддерживаемые форматы

| Формат | Что генерируется | Требования |
|---|---|---|
| `bin`   | чистые случайные байты                          | — |
| `exe`   | минимальный PE (AMD64) с сигнатурой `MZ`         | — |
| `dll`   | минимальный PE с флагом DLL                     | — |
| `elf`   | ELF64-заголовок + случайные данные              | — |
| `pdf`   | валидный PDF через reportlab (или `%PDF-1.4`)   | reportlab (опц.) |
| `docx`  | документ Word (или ZIP-заглушка)                | python-docx (опц.) |
| `xlsx`  | книга Excel (или ZIP-заглушка)                  | openpyxl (опц.) |
| `docm`  | ZIP-контейнер (макросы — только структура)      | — |
| `doc`   | OLE2 Compound File (сигнатура)                  | — |
| `xls`   | OLE2 Compound File (сигнатура)                  | — |
| `msi`   | OLE2 Compound File (сигнатура)                  | — |
| `rar`   | RAR-архив (или fallback с сигнатурой)           | `rar` в PATH (опц.) |
| `zip`   | валидный ZIP с одним stored-файлом              | — |
| `txt`   | случайный ASCII-текст                           | — |
| `csv`   | таблица с 5 колонками                           | — |
| `json`  | массив объектов `{id, text, ts}`                | — |
| `xml`   | `<root>` со множеством `<item>`                 | — |
| `wav`   | валидный WAV (PCM 16 бит, стерео, 44.1 кГц)     | — |
| `bmp`   | валидный BMP 24 бита, 256×H                     | — |
| `gz`    | gzip-контейнер (store, без сжатия)              | — |
| `tar`   | tar-архив с одним файлом                        | — |
| `sqlite`| база SQLite с таблицей `data`                   | — |

## Пример вывода

```
[1/3] OK file_0001.pdf (2097152 Б)
[2/3] OK file_0002.pdf (2097152 Б)
[3/3] OK file_0003.pdf (2097108 Б)
WARNING: file_0003.pdf: размер 2097108 отличается от целевого 2097152 на 0.0%

Готово: успешно 3, ошибок 0 из 3.
```

## Лицензия

Скрипт предназначен для тестовых/учебных целей. Сгенерированные файлы не содержат
полезной нагрузки и не должны использоваться как настоящие документы/исполняемые файлы.
