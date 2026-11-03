# CVE Description Parser

```python
#!/usr/bin/env python3

import os
import sys
import time
import argparse
from pathlib import Path
from typing import Optional, Any
import requests


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVEORG_API_URL = "https://cveawg.mitre.org/api/cve"
GITHUB_GRAPHQL_URL = "https://api.github.com/graphql"

NVD_DELAY_WITH_KEY = 1.0
NVD_DELAY_WITHOUT_KEY = 6.0
REQUEST_TIMEOUT = 30


def safe_get(data: Any, *keys, default=None):
    current = data
    for key in keys:
        if isinstance(current, dict):
            current = current.get(key)
        elif isinstance(current, list) and isinstance(key, int) and 0 <= key < len(current):
            current = current[key]
        else:
            return default
        if current is None:
            return default
    return current


def extract_cvss_from_nvd(cve_obj: dict) -> tuple[Optional[float], Optional[str]]:
    metrics = cve_obj.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries and isinstance(entries, list):
            cvss_data = entries[0].get("cvssData", {})
            score = cvss_data.get("baseScore")
            vector = cvss_data.get("vectorString")
            if score is not None:
                return score, vector
    return None, None


def extract_affected_from_nvd(cve_obj: dict) -> list[str]:
    products = []
    configurations = cve_obj.get("configurations", [])
    for config in configurations:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                criteria = match.get("criteria")
                if criteria:
                    products.append(criteria)
    seen = set()
    unique = []
    for p in products:
        if p not in seen:
            seen.add(p)
            unique.append(p)
    return unique


def extract_cvss_from_cveorg(cna: dict) -> tuple[Optional[float], Optional[str]]:
    metrics = cna.get("metrics", [])
    if not metrics:
        return None, None
    for metric in metrics:
        for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
            cvss = metric.get(key)
            if cvss and isinstance(cvss, dict):
                score = cvss.get("baseScore")
                vector = cvss.get("vectorString")
                if score is not None:
                    return score, vector
    return None, None


def extract_affected_from_cveorg(cna: dict) -> list[str]:
    products = []
    affected_list = cna.get("affected", [])
    for item in affected_list:
        vendor = item.get("vendor", "n/a")
        product = item.get("product", "n/a")
        versions = item.get("versions", [])
        version_strs = []
        for v in versions:
            ver = v.get("version")
            status = v.get("status", "")
            if ver:
                version_strs.append(f"{ver} ({status})" if status else ver)
        version_info = f" [{', '.join(version_strs)}]" if version_strs else ""
        products.append(f"{vendor} / {product}{version_info}")
    return products


def extract_cvss_from_github(advisory: dict) -> tuple[Optional[float], Optional[str]]:
    severities = advisory.get("cvssSeverities", {})
    for key in ("cvssV4", "cvssV3"):
        cvss = severities.get(key)
        if cvss and isinstance(cvss, dict):
            score = cvss.get("score")
            vector = cvss.get("vectorString")
            if score is not None:
                return score, vector
    cvss = advisory.get("cvss")
    if cvss and isinstance(cvss, dict):
        return cvss.get("score"), cvss.get("vectorString")
    return None, None


def extract_affected_from_github(advisory: dict) -> list[str]:
    products = []
    vulns = advisory.get("vulnerabilities", {}).get("nodes", [])
    for vuln in vulns:
        pkg = vuln.get("package", {})
        name = pkg.get("name", "n/a")
        ecosystem = pkg.get("ecosystem", "n/a")
        range_str = vuln.get("vulnerableVersionRange", "")
        fixed = vuln.get("firstPatchedVersion", {}).get("identifier", "")
        info = f"{ecosystem}:{name}"
        if range_str:
            info += f" (уязвимы: {range_str})"
        if fixed:
            info += f" [исправлено в: {fixed}]"
        products.append(info)
    return products


def get_nvd_data(
    cve_id: str, session: requests.Session, api_key: Optional[str] = None
) -> tuple[Optional[dict], Optional[str]]:
    params = {"cveId": cve_id}
    headers = {"apiKey": api_key} if api_key else {}

    try:
        resp = session.get(NVD_API_URL, params=params, headers=headers, timeout=REQUEST_TIMEOUT)
        if resp.status_code == 404:
            return None, "NVD: 404 (CVE отсутствует или ещё не опубликован)"
        resp.raise_for_status()
        data = resp.json()
        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return None, "NVD: пустой ответ"
        return vulnerabilities[0].get("cve"), None
    except requests.exceptions.HTTPError as e:
        status = getattr(e.response, "status_code", None)
        if status == 403:
            return None, "NVD: 403 (лимит запросов)"
        return None, f"NVD: HTTP {status or '?'}"
    except requests.exceptions.RequestException as e:
        return None, f"NVD: сетевая ошибка: {e}"
    except (KeyError, ValueError, TypeError) as e:
        return None, f"NVD: ошибка разбора JSON: {e}"


def get_cveorg_data(
    cve_id: str, session: requests.Session
) -> tuple[Optional[dict], Optional[str]]:
    url = f"{CVEORG_API_URL}/{cve_id}"
    try:
        resp = session.get(url, timeout=REQUEST_TIMEOUT)
        if resp.status_code == 404:
            return None, "CVE.org: 404 (запись не найдена)"
        resp.raise_for_status()
        data = resp.json()
        cna = data.get("containers", {}).get("cna")
        if not cna:
            return None, "CVE.org: отсутствует containers.cna"
        return cna, None
    except requests.exceptions.RequestException as e:
        return None, f"CVE.org: сетевая/HTTP-ошибка: {e}"
    except (KeyError, ValueError, TypeError) as e:
        return None, f"CVE.org: ошибка разбора JSON: {e}"



GITHUB_GRAPHQL_QUERY = """
query($cve: String!) {
  securityAdvisories(first: 1, identifiers: [{type: CVE, value: $cve}]) {
    nodes {
      description
      severity
      cvssSeverities {
        cvssV3 { score vectorString }
        cvssV4 { score vectorString }
      }
      vulnerabilities(first: 20) {
        nodes {
          vulnerableVersionRange
          firstPatchedVersion { identifier }
          package { name ecosystem }
        }
      }
    }
  }
}
"""


def get_github_data(
    cve_id: str, session: requests.Session, github_token: Optional[str] = None
) -> tuple[Optional[dict], Optional[str]]:
    if not github_token:
        return None, "GitHub: токен не задан"

    headers = {"Authorization": f"Bearer {github_token}", "Content-Type": "application/json"}
    payload = {"query": GITHUB_GRAPHQL_QUERY, "variables": {"cve": cve_id}}

    try:
        resp = session.post(GITHUB_GRAPHQL_URL, json=payload, headers=headers, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        if "errors" in data:
            return None, f"GitHub: ошибки GraphQL: {data['errors']}"
        nodes = safe_get(data, "data", "securityAdvisories", "nodes", default=[])
        if not nodes:
            return None, "GitHub: advisory не найден"
        return nodes[0], None
    except requests.exceptions.RequestException as e:
        return None, f"GitHub: сетевая/HTTP-ошибка: {e}"
    except (KeyError, ValueError, TypeError) as e:
        return None, f"GitHub: ошибка разбора JSON: {e}"


def fetch_cve_profile(
    cve_id: str,
    session: requests.Session,
    nvd_api_key: Optional[str] = None, # сюда NVD API
    github_token: Optional[str] = None,
) -> dict:
    errors = []

    cve_obj, err = get_nvd_data(cve_id, session, nvd_api_key)
    if cve_obj:
        desc = None
        for d in cve_obj.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value")
                break
        if not desc and cve_obj.get("descriptions"):
            desc = cve_obj["descriptions"][0].get("value")

        score, vector = extract_cvss_from_nvd(cve_obj)
        affected = extract_affected_from_nvd(cve_obj)
        return {
            "source": "NVD",
            "description": desc or "н/д",
            "score": score,
            "vector": vector,
            "affected": affected,
            "error": None,
        }
    elif err:
        errors.append(err)

    cna, err = get_cveorg_data(cve_id, session)
    if cna:
        desc = None
        for d in cna.get("descriptions", []):
            if str(d.get("lang", "")).lower().startswith("en"):
                desc = d.get("value")
                break
        if not desc and cna.get("descriptions"):
            desc = cna["descriptions"][0].get("value")

        score, vector = extract_cvss_from_cveorg(cna)
        affected = extract_affected_from_cveorg(cna)
        return {
            "source": "CVE.org",
            "description": desc or "н/д",
            "score": score,
            "vector": vector,
            "affected": affected,
            "error": None,
        }
    elif err:
        errors.append(err)

    advisory, err = get_github_data(cve_id, session, github_token)
    if advisory:
        desc = advisory.get("description") or "н/д"
        score, vector = extract_cvss_from_github(advisory)
        affected = extract_affected_from_github(advisory)
        return {
            "source": "GitHub Advisory",
            "description": desc,
            "score": score,
            "vector": vector,
            "affected": affected,
            "error": None,
        }
    elif err:
        errors.append(err)

    return {
        "source": None,
        "description": "Описание не найдено",
        "score": None,
        "vector": None,
        "affected": [],
        "error": "; ".join(errors),
    }


def main():
    parser = argparse.ArgumentParser(
        description="Получает описание, CVSS score и затронутые продукты для CVE."
    )
    parser.add_argument(
        "input_file",
        nargs="?",
        default="cve_list.txt",
        help="Файл со списком CVE (по одному на строку). По умолчанию: cve_list.txt",
    )
    parser.add_argument("--no-github", action="store_true", help="Отключить fallback на GitHub.")
    args = parser.parse_args()

    input_path = Path(args.input_file)
    if not input_path.exists():
        print(f"Ошибка: файл '{input_path}' не найден.", file=sys.stderr)
        sys.exit(1)

    with open(input_path, "r", encoding="utf-8") as f:
        cve_list = [
            line.strip()
            for line in f
            if line.strip() and not line.strip().startswith("#")
        ]

    if not cve_list:
        print("Файл не содержит CVE.", file=sys.stderr)
        sys.exit(1)

    nvd_api_key = os.environ.get("NVD_API_KEY")
    github_token = os.environ.get("GITHUB_TOKEN") if not args.no_github else None
    delay = NVD_DELAY_WITH_KEY if nvd_api_key else NVD_DELAY_WITHOUT_KEY

    print(f"Обработка {len(cve_list)} CVE...")
    if not nvd_api_key:
        print(f"Внимание: NVD_API_KEY не задан (задержка {delay} сек/запрос).")
    if not github_token and not args.no_github:
        print("Внимание: GITHUB_TOKEN не задан — fallback на GitHub будет пропущен.")
    print("=" * 80)

    with requests.Session() as session:
        for idx, cve_id in enumerate(cve_list, start=1):
            profile = fetch_cve_profile(
                cve_id, session, nvd_api_key=nvd_api_key, github_token=github_token
            )

            print(f"[{idx}/{len(cve_list)}] {cve_id}")
            print(f"  Источник : {profile['source'] or 'не найден'}")
            print(f"  Описание : {profile['description']}")

            # Score
            if profile["score"] is not None:
                print(f"  CVSS Score: {profile['score']}")
                if profile["vector"]:
                    print(f"  Вектор    : {profile['vector']}")
            else:
                print("  CVSS Score: н/д")

            # Affected Products
            if profile["affected"]:
                print("  Затронутые продукты:")
                for prod in profile["affected"]:
                    print(f"    - {prod}")
            else:
                print("  Затронутые продукты: н/д (не указаны в источнике)")

            if profile.get("error"):
                print(f"  Примечание: {profile['error']}")

            print("-" * 80)

            if idx < len(cve_list):
                time.sleep(delay)

    print("Готово.")


if __name__ == "__main__":
    main()
```
# CVE Description Parser

Скрипт на Python для получения подробной информации об уязвимостях CVE из нескольких источников с автоматическим каскадным fallback. Читает список CVE из файла и выводит для каждой уязвимости:

- **описание** (Description);
- **CVSS score** и вектор атаки;
- **список затронутых продуктов** (Affected Products);
- **источник**, из которого получены данные.

---

## Зачем это нужно

Официальная база **NVD** (National Vulnerability Database) — основной источник данных о CVE, но у неё есть существенная задержка: между публикацией CVE идентификатора со стороны CNA (например, GitHub) и появлением записи в NVD может пройти **от нескольких дней до нескольких недель**. В этот период NVD API отвечает `404`, хотя уязвимость уже описана в других публичных базах.

Этот скрипт решает проблему, опрашивая несколько источников по цепочке и используя первый, который вернул данные:

```
NVD  →  CVE.org (MITRE)  →  GitHub Advisory Database
```

В результате вы получаете актуальную информацию даже для самых свежих CVE, которые ещё не дошли до NVD.

---

## Возможности

- ✅ Каскадный fallback между тремя независимыми источниками данных.
- ✅ Извлечение **описания** на английском языке.
- ✅ Извлечение **CVSS score** и вектора (поддерживаются CVSS v2, v3.0, v3.1, v4.0).
- ✅ Извлечение списка **затронутых продуктов** (CPE-строки из NVD; вендор/продукт/версии из CVE.org; пакеты с диапазонами версий из GitHub).
- ✅ Уважение лимитов API (настраиваемые паузы между запросами к NVD).
- ✅ Поддержка API-ключей NVD и GitHub через переменные окружения (не нужно «зашивать» секреты в код).
- ✅ Подробные и понятные сообщения об ошибках по каждому источнику.
- ✅ Читаемый структурированный вывод.

---

## Требования

- **Python** 3.8 или выше.
- Библиотека **requests** (`pip install requests`).
- (Опционально) API-ключ **NVD** — настоятельно рекомендуется для списков > 5 CVE.
- (Опционально) **GitHub Personal Access Token** — нужен только для fallback на GitHub Advisory.

---

## Установка

1. Склонируйте/сохраните скрипт как `cve_description_parser.py`.
2. Установите зависимости:

   ```bash
   pip install requests
   ```

3. (Опционально) создайте файл `cve_list.txt` рядом со скриптом — см. раздел ниже.

---

## Настройка ключей API

Скрипт читает ключи из **переменных окружения**, чтобы не хранить секреты в исходном коде.

### NVD API Key (настоятельно рекомендуется)

Получить бесплатно: https://nvd.nist.gov/developers/request-an-api-key

```bash
# Linux / macOS
export NVD_API_KEY="ваш_ключ"

# Windows PowerShell
$env:NVD_API_KEY="ваш_ключ"

# Windows cmd
set NVD_API_KEY=ваш_ключ
```

Без ключа NVD разрешает ~5 запросов за 30 секунд. С ключом — ~50 запросов за 30 секунд.

### GitHub Token (опционально)

Нужен только для fallback на GitHub Advisory Database, когда ни NVD, ни CVE.org не вернули данные.

1. Откройте https://github.com/settings/tokens
2. Создайте **classic token** с правами `read:packages` (или fine-grained token с доступом к public advisories).
3. Задайте переменную:

```bash
export GITHUB_TOKEN="ghp_ваш_токен"
```

Если токен не задан — fallback на GitHub просто будет пропущен (с предупреждением в начале работы).

---

## Формат входного файла

Файл со списком CVE — обычный текстовый файл, **один CVE на строку**.

```text
CVE-2026-96636
CVE-2026-96637
CVE-2026-96638
# строки, начинающиеся с #, игнорируются как комментарии
CVE-2024-12345
```

- Пустые строки пропускаются.
- Идентификаторы должны быть в полном формате `CVE-YYYY-NNNNN`.

---

## Запуск

```bash
# с файлом по умолчанию (cve_list.txt)
python cve_description_parser.py

# с указанием файла
python cve_description_parser.py my_cves.txt

# отключить fallback на GitHub
python cve_description_parser.py my_cves.txt --no-github
```

### Аргументы командной строки

| Аргумент | По умолчанию | Описание |
|---|---|---|
| `input_file` | `cve_list.txt` | Путь к файлу со списком CVE. |
| `--no-github` | выкл. | Отключить fallback на GitHub Advisory. |
| `-h`, `--help` | — | Показать справку. |

---

## Пример вывода

```text
Обработка 3 CVE...
================================================================================
[1/3] CVE-2024-12345
  Источник : NVD
  Описание : A vulnerability in Example Product allows remote attackers ...
  CVSS Score: 7.5
  Вектор    : CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
  Затронутые продукты:
    - cpe:2.3:a:example:product:*:*:*:*:*:*:*:*
--------------------------------------------------------------------------------
[2/3] CVE-2026-96636
  Источник : CVE.org
  Описание : Pillow before 13.0.0 re-parses subsequent frames ...
  CVSS Score: 5.3
  Вектор    : CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L
  Затронутые продукты:
    - python / pillow [< 13.0.0 (affected)]
--------------------------------------------------------------------------------
[3/3] CVE-2026-99999
  Источник : GitHub Advisory
  Описание : ...
  CVSS Score: 6.1
  Вектор    : CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N
  Затронутые продукты:
    - npm:some-package (уязвимы: < 2.0.0) [исправлено в: 2.0.0]
--------------------------------------------------------------------------------
Готово.
```

---

## Архитектура и источники данных

Скрипт опрашивает источники **строго по порядку**, и как только один из них вернул данные, работа с этим CVE прекращается:

```
┌─────────┐   404/ошибка    ┌──────────┐   404/ошибка    ┌───────────────────┐
│   NVD   │ ──────────────► │ CVE.org  │ ──────────────► │ GitHub Advisory   │
└─────────┘                 └──────────┘                 └───────────────────┘
     │                           │                               │
     └───────────────────────────┴───────────────────────────────┘
              успешный ответ → вывод профиля CVE
```

### Источник 1 — NVD API 2.0

- **URL**: `https://services.nvd.nist.gov/rest/json/cves/2.0`
- **Аутентификация**: `apiKey` в HTTP-заголовке (опционально).
- **Плюсы**: официальный источник, богатые метаданные (CPE, CVSS, CWE, ссылки).
- **Минусы**: задержка публикации новых CVE; жёсткие лимиты без ключа.
- **Ответ 404**: CVE отсутствует в NVD или ещё не опубликован.

### Источник 2 — CVE.org (MITRE CVE Services API)

- **URL**: `https://cveawg.mitre.org/api/cve/{CVE-ID}`
- **Аутентификация**: не требуется.
- **Плюсы**: содержит данные **напрямую от CNA** сразу после публикации; часто опережает NVD на дни/недели.
- **Минусы**: структура неоднородна — каждый CNA может заполнять поля по-своему; поля CVSS и affected опциональны.

### Источник 3 — GitHub Advisory Database (GraphQL)

- **URL**: `https://api.github.com/graphql`
- **Аутентификация**: `Authorization: Bearer <GITHUB_TOKEN>`.
- **Плюсы**: очень быстро получает данные для CVE, опубликованных GitHub CNA (а их много в экосистеме npm, pip, Go, Rust и т.д.); содержит точные диапазоны уязвимых и исправленных версий.
- **Минусы**: покрывает только CVE, зарегистрированные через GitHub Security Advisories.

---

## Как извлекаются поля

### CVSS score

Извлечение идёт «по лесенке» от новых версий CVSS к старым:

| Источник | Порядок полей |
|---|---|
| **NVD** | `cvssMetricV40` → `cvssMetricV31` → `cvssMetricV30` → `cvssMetricV2` |
| **CVE.org** | `cvssV4_0` → `cvssV3_1` → `cvssV3_0` → `cvssV2_0` |
| **GitHub** | `cvssSeverities.cvssV4` → `cvssSeverities.cvssV3` → устаревшее `cvss` |

Возвращается первое непустое значение `baseScore` вместе с `vectorString`.

### Affected Products

| Источник | Откуда берётся | Как выглядит вывод |
|---|---|---|
| **NVD** | `cve.configurations[].nodes[].cpeMatch[].criteria` | `cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*` |
| **CVE.org** | `containers.cna.affected[]` | `vendor / product [1.0.0 (affected), < 2.0.0 (unaffected)]` |
| **GitHub** | `vulnerabilities.nodes[]` | `ecosystem:package (уязвимы: < 2.0.0) [исправлено в: 2.0.0]` |

Дубликаты CPE-строк из NVD удаляются с сохранением порядка.

### Description

Для NVD и CVE.org выбирается описание с `lang == "en"`; если английского нет — берётся первое доступное. Для GitHub — поле `description` напрямую.

---

## Обработка ошибок

Скрипт никогда не падает из-за проблем одного источника — он аккумулирует сообщения об ошибках и продолжает работу со следующим.

| Ситуация | Что происходит |
|---|---|
| NVD вернул 404 | Пробуем CVE.org |
| NVD вернул 403 | Логируем «лимит запросов», пробуем CVE.org |
| Сетевая ошибка / таймаут | Логируем, пробуем следующий источник |
| Некорректный JSON | Логируем, пробуем следующий источник |
| GitHub-токен не задан | Fallback на GitHub пропускается с предупреждением |
| Все источники пусты | Выводим сводку причин по каждому источнику |

Если ни один источник не дал данных, в конце выводится строка с перечнем причин:

```
Примечание: NVD: 404 (CVE отсутствует или ещё не опубликован);
            CVE.org: 404 (запись не найдена);
            GitHub: advisory не найден
```

---

## Лимиты API и задержки

Скрипт делает паузу **только между запросами к NVD**, поскольку fallback-источники (CVE.org, GitHub) не имеют таких жёстких публичных лимитов.

| Режим | Задержка | Пропускная способность |
|---|---|---|
| Без `NVD_API_KEY` | **6 сек** | ~5 CVE/мин |
| С `NVD_API_KEY` | **1 сек** | ~60 CVE/мин |

Задержка определяется автоматически в начале работы. Если файл содержит много CVE, а ключа NVD нет — обработка займёт заметное время (39 CVE ≈ 4 минуты). Настоятельно рекомендуется получить бесплатный ключ.

---

## Известные ограничения

- **Только английские описания.** Если у CVE есть лишь не-английское описание, оно будет выведено как fallback (без перевода).
- **Формат `Affected Products` зависит от источника.** CPE-строки из NVD и структурированные `vendor/product` из CVE.org нельзя напрямую сравнивать — это разные модели данных.
- **Не все CVE имеют CVSS.** Особенно свежие записи от CNA могут не содержать метрик — в этом случае выводится `CVSS Score: н/д`.
- **GitHub fallback покрывает только CVE от GitHub CNA.** Для CVE от других CNA (например, Apache, Microsoft) GitHub-источник бесполезен.
- **Нет кэширования.** При повторных запусках все запросы выполняются заново. Для больших списков имеет смысл добавить локальный кэш (не реализовано).
- **Нет вывода в файл.** По умолчанию результаты печатаются в stdout — их можно перенаправить (`> result.txt`). Встроенного флага `--output` нет.

---

## Структура кода

Скрипт организован по слоям — легко расширять и добавлять новые источники.

```
cve_description_parser.py
│
├── Конфигурация (URL, таймауты, задержки)
│
├── Утилиты
│   └── safe_get()                        — безопасный доступ к вложенным полям
│
├── Экстракторы полей
│   ├── extract_cvss_from_nvd()
│   ├── extract_affected_from_nvd()
│   ├── extract_cvss_from_cveorg()
│   ├── extract_affected_from_cveorg()
│   ├── extract_cvss_from_github()
│   └── extract_affected_from_github()
│
├── Источники данных
│   ├── get_nvd_data()                    — NVD API 2.0
│   ├── get_cveorg_data()                 — CVE.org (MITRE)
│   └── get_github_data()                 — GitHub Advisory (GraphQL)
│
├── Оркестратор
│   └── fetch_cve_profile()               — каскадный fallback + сборка профиля
│
└── main()                                — CLI, чтение файла, цикл обработки
```

Чтобы добавить новый источник, достаточно:
1. Написать функцию `get_xxx_data()` — запрос и возврат «сырого» объекта.
2. Написать экстракторы `extract_cvss_from_xxx()` и `extract_affected_from_xxx()`.
3. Вставить блок в `fetch_cve_profile()` — обычно между NVD и CVE.org или после GitHub.

---

## Частые вопросы

**Вопрос:** Все CVE возвращают `404` от NVD. Это баг?
**Ответ:** Нет. Скорее всего, эти CVE ещё не опубликованы в NVD. Скрипт автоматически попробует CVE.org и GitHub. Если и там нет — значит, запись ещё не дошла ни до одной базы (такое бывает в первые часы после публикации CNA).

**Вопрос:** Как ускорить работу для 1000 CVE?
**Ответ:** Получите `NVD_API_KEY` — это ускорит работу примерно в 6 раз (1 сек вместо 6 сек на CVE). Также можно увеличить `REQUEST_TIMEOUT` и `NVD_DELAY_WITH_KEY` (например, до 0.7 сек), но рискуете словить 403 при всплесках нагрузки.

**Вопрос:** Почему у некоторых CVE пустой `Affected Products`?
**Ответ:** NVD заполняет `configurations` только после собственного анализа (статус `Analyzed`). Свежие CVE обычно имеют статус `Awaiting Analysis` — CPE-строк там нет. CVE.org и GitHub заполняют `affected` не всегда. Это ограничение источников, а не скрипта.

**Вопрос:** Где взять `GITHUB_TOKEN`?
**Ответ:** https://github.com/settings/tokens → «Generate new token (classic)» → отметьте `read:packages` (или fine-grained token с доступом к public advisories). Токен долгоживущий, храните его в переменной окружения.

**Вопрос:** Как сохранить результат в файл?
**Ответ:** Стандартное перенаправление:

```bash
python cve_description_parser.py > result.txt
```

Или в формате, удобном для Excel:

```bash
python cve_description_parser.py | tee result.txt
```

**Вопрос:** Можно ли использовать скрипт как модуль из другого кода?
**Ответ:** Да. Импортируйте `fetch_cve_profile` и вызовите её с готовой `requests.Session`:

```python
from cve_description_parser import fetch_cve_profile
import requests

with requests.Session() as s:
    profile = fetch_cve_profile("CVE-2026-96636", s, nvd_api_key="...", github_token="...")
    print(profile["description"], profile["score"], profile["affected"])
```

---

## Лицензия

Скрипт использует только публичные API. Пожалуйста, соблюдайте условия использования каждого источника:

- NVD API: https://nvd.nist.gov/developers/terms-of-use
- CVE Services API: https://cveawg.mitre.org/api-docs/
- GitHub GraphQL API: https://docs.github.com/en/graphql

Скрипт предоставляется «как есть» без каких-либо гарантий.
