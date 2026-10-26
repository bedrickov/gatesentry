# GateSentry

<div align="center">

![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-0078D4?style=flat-square&logo=linux)
![Runtime](https://img.shields.io/badge/.NET-10.0%20LTS-512BD4?style=flat-square&logo=dotnet)
![Architecture](https://img.shields.io/badge/Architecture-x64%20%2F%20ARM64-informational?style=flat-square)
![SARIF Spec](https://img.shields.io/badge/SARIF-OASIS%20v2.1-blue?style=flat-square)
![Dependencies](https://img.shields.io/badge/Dependencies-Zero%20(Pure%20BCL)-success?style=flat-square)
![License](https://img.shields.io/badge/License-Apache%202.0-blue?style=flat-square)

**Высокопроизводительный DevSecOps статический анализатор кода и сканер секретов.**  
*Многопоточный аудит репозиториев, валидация криптографической энтропии Шеннона, маскирование токенов и нативный экспорт в GitHub Code Scanning (SARIF v2.1).*

[О проекте](#о-проекте) • [Возможности](#возможности) • [Архитектура](#архитектура) • [Сборка](#сборка-из-исходников) • [CLI и CI/CD](#использование-cli) • [Правила обнаружения](#каталог-правил)

</div>

---

## О проекте

Большинство сторонних сканеров секретов страдают двумя ключевыми проблемами:
1. **Каскад ложных срабатываний**: примитивные регулярные выражения спотыкаются о тестовые строки вроде `AKIA0000000000000000` или `password="secret"`.
2. **Утечка конфиденциальных данных в логи**: при обнаружении уязвимости CLI выводит секрет целиком в открытый лог сборки CI/CD, фактически компрометируя его еще раз.

**GateSentry** спроектирован с упором на надежность, предсказуемость системных вызовов и интеграцию в современные пайплайны разработки:
- **Нулевые сторонние зависимости**: использует только стандартную библиотеку (.NET 10 BCL), что исключает supply-chain атаки на сам анализатор.
- **Двойная валидация (Regex + Shannon Entropy)**: кандидаты в токены анализируются по формуле информационной энтропии Шеннона, отсеивая низкоэнтропийные заглушки.
- **Детерминированное маскирование (Redaction)**: перед выводом в консоль или лог токен надежно маскируется (`AKI**************PLE`).
- **Снимок базового состояния (Baseline)**: сохранение известных легаси-проблем в `.gatesentry-baseline.json` для поэтапного устранения техдолга без остановки деплоев.
- **Стандарт OASIS SARIF v2.1**: результаты сканирования напрямую загружаются в **GitHub Security -> Code scanning alerts**.

---

## Возможности

- **Параллельное сканирование на уровне ядер**: распределение файлов через `Parallel.ForEachAsync` с автоматическим контролем аллокаций.
- **Обнаружение утечек облачной инфраструктуры**: AWS Access Keys, AWS Secret Access Keys, GCP/Azure Service Credentials.
- **Контроль аутентификации разработчиков**: GitHub PATs (классические `ghp_` и fine-grained `github_pat_`), GitLab Personal Tokens.
- **Поиск незашифрованных криптографических ключей**: RSA, EC, OPENSSH, DSA, PGP Private Key Headers.
- **Защита современных LLM и чат-ботов**: OpenAI API (`sk-...`), Anthropic API (`sk-ant-...`), Telegram Bot Tokens, Slack Webhook/App Tokens.
- **Аудит конфигураций безопасности**:
  - Строки подключения к БД (PostgreSQL, MySQL, MongoDB, Redis, MSSQL) с открытыми паролями.
  - Опасные отключения валидации TLS/SSL (`ServerCertificateCustomValidationCallback => true`, `rejectUnauthorized: false`, `verify=False`).
  - Статические симметричные ключи подписи JWT токенов.
  - Запуск контейнеров от имени `root`.
- **Inline подавление**: возможность точечного игнорирования безопасных строк через комментарии `// gatesentry:ignore` или `# gatesentry:ignore`.

---

## Архитектура

Проект организован по стандартам корпоративной разработки:

```
GateSentry/
├── .github/workflows/
│   └── build.yml                   # CI/CD: Сборка, xUnit тесты, самосканирование и выгрузка SARIF
├── src/
│   ├── GateSentry.Core/            # Чистая библиотека ядра (NetStandard/Net10)
│   │   ├── Analysis/               # Расчет энтропии Шеннона, хеширование SHA-256 и маскирование
│   │   ├── Config/                 # Модели опций и сериализация Baseline
│   │   ├── Engine/                 # Многопоточный диспетчер сканирования файлов
│   │   ├── Formatters/             # Форматирование OASIS SARIF v2.1 и JSON
│   │   ├── Models/                 # Записи (Records) и типы уровней серьезности
│   │   └── Rules/                  # Встроенный каталог правил безопасности
│   └── GateSentry.Cli/             # Консольный интерфейс с ANSI-рендерингом
├── tests/
│   └── GateSentry.Tests/           # Сьют юнит-тестов (xUnit)
├── build.bat / build.ps1           # Кроссплатформенные скрипты автоматизации сборки
├── LICENSE                         # Лицензия Apache-2.0
└── GateSentry.slnx                 # Solution
```

---

## Сборка из исходников

### Требования
- [.NET 10 SDK](https://dotnet.microsoft.com/)
- Windows, Linux или macOS

### Быстрый билд через скрипт
```powershell
# Сборка проекта и прогон юнит-тестов
.\build.ps1 -Test

# Очистка артефактов сборки
.\build.ps1 -Clean
```

Или через стандартный `dotnet CLI`:
```bash
dotnet restore GateSentry.slnx
dotnet build GateSentry.slnx -c Release
dotnet test GateSentry.slnx -c Release
```

---

## Использование CLI

```bash
# Базовое сканирование текущей папки
dotnet run --project src/GateSentry.Cli -- scan .

# Сканирование с генерацией SARIF отчета для CI
dotnet run --project src/GateSentry.Cli -- scan . --sarif scan-results.sarif

# Порог ошибки: прерывать билд только при Critical уязвимостях
dotnet run --project src/GateSentry.Cli -- scan . --fail-on Critical

# Создание baseline-файла для подавления существующих находок
dotnet run --project src/GateSentry.Cli -- baseline .

# Анализ энтропии произвольной строки
dotnet run --project src/GateSentry.Cli -- entropy "4a8B+9cK1lMnOpQrStUvWxYz0123456789+AbCdE="

# Вывод каталога активных правил
dotnet run --project src/GateSentry.Cli -- rules
```

---

## Каталог правил

| ID | Важность | Категория | Описание |
| :--- | :--- | :--- | :--- |
| **GS-001** | `Critical` | CloudCredential | Идентификаторы AWS Access Key (`AKIA...`) |
| **GS-002** | `Critical` | CloudCredential | Секретные ключи AWS Secret Access Key с проверкой энтропии |
| **GS-003** | `Critical` | Secret | Персональные токены доступа GitHub (PAT) |
| **GS-004** | `Critical` | PrivateKey | Заголовки закрытых криптографических ключей RSA / EC / SSH |
| **GS-005** | `High` | Secret | Высокоэнтропийные API токены и ключи сервисов |
| **GS-006** | `High` | Secret | Боты и токены интеграций Slack (`xoxb-...`) |
| **GS-007** | `High` | Secret | Аутентификационные токены Telegram Bot API |
| **GS-008** | `High` | Misconfiguration | Строки подключения к БД с открытыми учетными данными |
| **GS-009** | `Critical` | Secret | Платные API ключи нейросетей OpenAI и Anthropic |
| **GS-010** | `Medium` | Misconfiguration | Отключение проверки SSL/TLS сертификатов |
| **GS-011** | `High` | WeakCryptography | Захардкоженные симметричные ключи подписи JWT |
| **GS-012** | `Low` | Misconfiguration | Запуск Docker-контейнера от пользователя root |

---

## Интеграция с GitHub Actions

Добавьте шаг в `.github/workflows/security.yml`:

```yaml
- name: Run GateSentry Security Audit
  run: dotnet run --project src/GateSentry.Cli -- scan . --sarif results.sarif --fail-on High

- name: Upload to GitHub Code Scanning
  uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: results.sarif
```

---

## Лицензия

Проект распространяется под лицензией **Apache License 2.0**. Подробности в файле [LICENSE](LICENSE).
