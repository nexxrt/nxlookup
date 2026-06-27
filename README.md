# nxlookup

> Ultimate Domain & IP Investigation Tool  
> Полная разведка по домену или IP за одну команду

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://python.org)

---

`nxlookup` собирает **всю информацию** по домену или IP-адресу: whois, DNS-записи всех типов, данные о провайдере/ASN для каждого IP из A/AAAA-записей, PTR, abuse-контакты. Всё в одном цветном отчёте.

**90+ доменных зон** (ru, рф, com, net, org, it, de, fr, uk, cn, io, me, tv и десятки других).  
**IDN-домены** (объясняем.рф, 百度.cn).  
**URL на входе** (https://..., www., путь — отрезается автоматически).

---

## Что умеет

```
┌─ WHOIS ─────────────────────────────────────────┐
│ Registrar, даты, статусы, DNS-серверы            │
│ + авто-резолв IP каждого NS                      │
├─ DNS ───────────────────────────────────────────┤
│ A, AAAA, MX, NS, TXT, SOA, CNAME                 │
├─ IP ANALYSIS ───────────────────────────────────┤
│ PTR, провайдер/ASN, диапазон, страна, abuse      │
├─ QUICK SUMMARY ─────────────────────────────────┤
│ Сводка в 6 строк                                 │
└─────────────────────────────────────────────────┘
```

---

## Установка

### Способ 1: одной командой (Linux / macOS / WSL)

```bash
sudo curl -sSL https://raw.githubusercontent.com/nexxrt/nxlookup/main/nxlookup.py -o /usr/local/bin/nxlookup && sudo chmod +x /usr/local/bin/nxlookup
```

Всё. После этого команда `nxlookup` доступна из любого места.

---

### Способ 2: Windows через WSL (для новичков)

Если у вас Windows и вы никогда не пользовались WSL — вот пошаговая инструкция с нуля.

#### Шаг 1. Установка WSL

Откройте **PowerShell от имени администратора** (ПКМ по Пуск → PowerShell (Администратор)) и выполните:

```powershell
wsl --install
```

Компьютер перезагрузится. После перезагрузки откроется окно Ubuntu — создайте имя пользователя и пароль (запомните пароль, он понадобится для `sudo`).

Если WSL уже был установлен, просто откройте **Ubuntu** из меню Пуск.

#### Шаг 2. Установка зависимостей

В открытом терминале Ubuntu выполните:

```bash
sudo apt update
sudo apt install -y dnsutils whois python3
```

Это установит `dig`, `whois` и Python (обычно уже есть).

> **Примечание для Arch/WSL:** `sudo pacman -S bind whois python`

#### Шаг 3. Установка nxlookup

```bash
sudo curl -sSL https://raw.githubusercontent.com/nexxrt/nxlookup/main/nxlookup.py -o /usr/local/bin/nxlookup
sudo chmod +x /usr/local/bin/nxlookup
```

#### Шаг 4. Проверка

```bash
nxlookup --version
```

Должно вывести: `nxlookup v1.0.0 — Ultimate Domain/IP Investigation Tool`

#### Шаг 5. Первый запуск

```bash
nxlookup yandex.ru
```

Готово! Вы увидите полную сводку по домену.

---

### Способ 3: ручная установка из репозитория

```bash
git clone https://github.com/nexxrt/nxlookup.git
cd nxlookup
sudo cp nxlookup.py /usr/local/bin/nxlookup
sudo chmod +x /usr/local/bin/nxlookup
```

---

### Зависимости

Обязательно должны быть установлены:

| Пакет | Debian/Ubuntu | Arch | macOS (brew) | RHEL/Fedora |
|-------|--------------|------|-------------|-------------|
| `dig` | `sudo apt install dnsutils` | `sudo pacman -S bind` | `brew install bind` | `sudo dnf install bind-utils` |
| `whois` | `sudo apt install whois` | `sudo pacman -S whois` | `brew install whois` | `sudo dnf install whois` |
| Python 3 | уже есть | уже есть | уже есть | уже есть |

**Никаких pip-зависимостей** — только стандартная библиотека Python.

---

## Использование

### Домен

```bash
nxlookup yandex.ru
nxlookup github.com
nxlookup example.org
```

### IP-адрес

```bash
nxlookup 8.8.8.8
nxlookup 1.1.1.1
```

### IDN-домен (кириллица, иероглифы)

```bash
nxlookup объясняем.рф
nxlookup президент.рф
```

### URL на входе (протокол и путь отрезаются автоматически)

```bash
nxlookup https://www.example.com/path/to/page
nxlookup http://github.com/nousresearch/hermes-agent
```

### Интерактивный режим

```bash
nxlookup
# Введите домен или IP, когда спросит
```

### Справка

```bash
nxlookup --help
nxlookup --version
```

---

## Пример вывода

```
$ nxlookup github.com

╔══════════════════════════════════════════════════╗
║  nxlookup — Ultimate Domain/IP Investigation          ║
╚══════════════════════════════════════════════════╝

  Target: github.com (domain)

━━━ 1. WHOIS DATA ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Domain:          GITHUB.COM
  Registrar:       MarkMonitor Inc.
  Created:         2007-10-09T18:20:50Z
  Expires:         2026-10-09T18:20:50Z
  Status:          clientDeleteProhibited
                   clientTransferProhibited
                   clientUpdateProhibited
  ▸ DNS Servers (from WHOIS)
    [1] DNS1.P08.NSONE.NET  →  198.51.44.8
    [2] DNS2.P08.NSONE.NET  →  198.51.45.8
    [3] NS-421.AWSDNS-52.COM  →  205.251.193.165
    ... и ещё 5 серверов

━━━ 2. DNS RESOURCE RECORDS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ▸ A Records (1)
    140.82.121.4
  ▸ MX Records (1)
    0 github-com.mail.protection.outlook.com
  ▸ NS Records (8)
    dns1.p08.nsone.net
    dns2.p08.nsone.net
    ns-421.awsdns-52.com
    ... и ещё 5 серверов

━━━ 3. IP ADDRESS ANALYSIS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ▸ 140.82.121.4
    PTR:             lb-140-82-121-4-fra.github.com
    Organization:    GitHub, Inc.
    NetName:         GITHU
    Range:           140.82.112.0 - 140.82.127.255
    Country:         US
    Abuse Contact:   noc@github.com

━━━ 4. QUICK SUMMARY ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Domain:       github.com
  Registrar:    MarkMonitor Inc.
  Expires:      2026-10-09T18:20:50Z
  Nameservers:  8 found
  A Records:    1 — 140.82.121.4
  MX Records:  1
```

---

## Поддерживаемые доменные зоны

`nxlookup` использует системный `whois` с расширенным конфигом (`/etc/whois.conf`), покрывающим **90+ зон**:

| Регион | Зоны |
|--------|------|
| Россия/СНГ | .ru, .рф, .su, .kz, .by, .uz, .kg, .tj, .tm, .az, .ge, .am, .md, .ua |
| Европа | .eu, .it, .de, .fr, .nl, .be, .ch, .at, .es, .pt, .pl, .se, .no, .dk, .fi, .ie, .cz, .sk, .hu, .lt, .lv, .ee, .lu, .is, .gr |
| UK | .uk, .co.uk, .org.uk, .me.uk |
| Азия | .cn, .jp, .kr, .in, .sg, .au, .nz, .hk, .tw, .ph, .my |
| gTLD | .com, .net, .org, .info, .biz, .pro (RDAP), .name, .mobi, .xxx, .tel, .aero, .asia, .cat |
| New gTLD | .xyz, .top, .club, .online, .site, .shop, .blog, .app, .dev, .cloud, .tech, .digital, .email, .guru, .link, .live, .media, .rocks, .solutions, .space, .today, .website, .world, .zone |
| Островные | .io, .me, .tv, .cc, .ws, .tk |
| Америка | .ca, .br, .mx, .us, .co, .pe, .cl, .ar |

> ⚠️ `.pro` — RDAP-only (whois по порту 43 отключён), запрос через HTTPS.

---

## Частые вопросы

**Q: «Почему whois пустой для некоторых доменов?»**  
Некоторые зоны (.it, .de) ограничивают whois-выдачу из-за GDPR. DNS-записи и IP-анализ при этом работают полностью.

**Q: «Можно ли без sudo?»**  
Да, скопируйте скрипт в любую директорию из `$PATH` (например, `~/.local/bin/`) и дайте права на исполнение.

**Q: «Не работает на macOS?»**  
Установите `dig` и `whois` через Homebrew: `brew install bind whois`

**Q: «Как обновить nxlookup?»**  
Повторите команду установки (curl …) — она перезапишет скрипт новой версией.

---

## Дорожная карта

- [x] WHOIS-парсер для 90+ зон
- [x] Все типы DNS-записей (A, AAAA, MX, NS, TXT, SOA, CNAME)
- [x] IP/ASN-анализ с PTR и abuse-контактами
- [x] IDN-домены (кириллица, иероглифы)
- [x] Очистка URL на входе (https://, www., путь)
- [x] Интерактивный режим
- [ ] Windows .exe (PyInstaller)
- [ ] Экспорт в JSON
- [ ] Проверка SSL-сертификата
- [ ] Геолокация IP

---

## Автор

**nexx** — [github.com/nexxrt](https://github.com/nexxrt)

---

## Лицензия

MIT — делайте что хотите. [LICENSE](LICENSE)
