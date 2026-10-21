# Разбор шифровальщика X

> [!WARNING]
> Образец вредоносный. Работайте в изолированной ВМ без сети, снапшот до запуска.

Краткое описание образца и находок.

## TL;DR

Семейство: **X**, шифрует файлы через AES-256, C2 — HTTPS.

## Статический анализ

```bash
strings sample.bin | grep -Ei 'http|cmd|vssadmin'
```

> [!NOTE]
> Строки могут быть зашифрованы — ищите XOR-ключ в `.data`.

## Динамический анализ

### Procmon

Смотрим на `CreateFile` и `WriteFile`.

> [!TIP]
> В Wireshark фильтр `tls.handshake.extensions_server_name` сразу покажет SNI.

## IOC

```
sha256: 3f2a...c1d
c2:     hxxps://evil[.]example[.]com/gate.php
mutex:  Global\X_9f3a
```

> [!DANGER]
> Не запускайте образец на хосте с доступом в интернет.
