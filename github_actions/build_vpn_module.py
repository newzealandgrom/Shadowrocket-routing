#!/usr/bin/env python3
"""
Сборка modules/VPN-Detect-RU.module — модуля для приложений, которые жалуются на VPN или прокси.

Запуск:
    python github_actions/build_vpn_module.py           # пересобрать модуль
    python github_actions/build_vpn_module.py --check   # exit 1, если модуль устарел

Что делает модуль:
  * skip-proxy: домены банков и госсервисов обрабатываются интерфейсом TUN, а не прокси-интерфейсом
    Shadowrocket. Приложение, которое спрашивает у iOS, идёт ли его адрес через прокси, получает «нет».
    Маршрут не меняется: банки и так идут напрямую по спискам конфига.
  * параметр tun: по желанию включает режим «только TUN» (compatibility-mode = 3, в приложении это
    Настройки → Тип прокси → None). Тогда системный HTTP-прокси не выставляется вовсе, и приложения
    не видят его ни для каких адресов.

Почему список skip-proxy повторяет SR_RU.conf: значение из модуля может заменить значение конфига,
а дописывание (%APPEND%) для [General] в руководстве Shadowrocket не описано. Поэтому модуль содержит
весь skip-proxy конфига плюс свои домены: результат одинаковый в обоих случаях.

always-real-ip модуль не трогает: в SR_RU.conf уже стоит always-real-ip = *, а значение из модуля
заменило бы его и включило подменные IP для всех остальных доменов.

Домены: весь skip-proxy конфига (там уже есть *.ru), зоны *.su и *.рф, домены банков из
lists/domains_banking.list вне этих зон и несколько доменов госсервисов и платёжных сервисов.
"""
from __future__ import annotations

import argparse
import os
import re
import sys

CONF = "SR_RU.conf"
BANKING = "lists/domains_banking.list"
OUT = "modules/VPN-Detect-RU.module"

# Зоны, которые целиком добавляются шаблоном (*.ru уже есть в skip-proxy конфига).
ZONES = ["ru", "su", "xn--p1ai"]
# Госсервисы и платёжные сервисы вне российских зон, которых нет в списке ЦБ.
EXTRA_DOMAINS = [
    "emias.info",
    "tbank-online.com",
    "yandex-bank.net",
    "beta-bank.com",
    "investalfabank.com",
    "vtb24.com",
    "vtb-russia.com",
    "vtbrussia.com",
]

HEADER = """#!name=Приложения, которые жалуются на VPN
#!desc=Для банков и госсервисов iOS перестаёт сообщать о прокси: их домены обрабатывает TUN-интерфейс Shadowrocket. По желанию включает режим «только TUN». Маршрут трафика не меняется. Конфиг не правит, выключается переключателем.
#!arguments=extra:#домены через запятую,tun:#compatibility-mode=3
#!arguments-desc=extra: свои домены через запятую, например app.example.com, *.example.com. Значение по умолчанию начинается с # и ничего не добавляет\\n\\ntun: чтобы включить режим «только TUN», удалите # в начале, должно остаться compatibility-mode=3. Системный прокси перестанет выставляться для всех приложений. Приложения, которые проверяют сам факт VPN-подключения, этот модуль не обманет
#!homepage=https://github.com/newzealandgrom/Shadowrocket-routing
# Файл генерирует github_actions/build_vpn_module.py из SR_RU.conf и lists/domains_banking.list.
"""


def conf_skip_proxy() -> list[str]:
    text = open(CONF, encoding="utf-8").read()
    m = re.search(r"^skip-proxy\s*=\s*(.*)$", text, re.M)
    if not m:
        raise RuntimeError(f"в {CONF} нет skip-proxy")
    return [x.strip() for x in m.group(1).split(",") if x.strip()]


def banking_domains() -> list[str]:
    out = []
    for line in open(BANKING, encoding="utf-8"):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        rtype, _, rest = s.partition(",")
        if rtype not in ("DOMAIN", "DOMAIN-SUFFIX"):
            continue
        out.append(rest.split(",")[0].strip().lower())
    return out


def in_zones(domain: str) -> bool:
    return any(domain == z or domain.endswith("." + z) for z in ZONES)


def build() -> str:
    items = conf_skip_proxy()
    for z in ZONES:
        pattern = f"*.{z}"
        if pattern not in items:
            items.append(pattern)
    domains = sorted({d for d in banking_domains() + EXTRA_DOMAINS if not in_zones(d)})
    for d in domains:
        for entry in (d, f"*.{d}"):
            if entry not in items:
                items.append(entry)
    body = [
        "[General]",
        "# Повторяет skip-proxy из SR_RU.conf и добавляет банки и госсервисы.",
        "skip-proxy = " + ", ".join(items) + ", {{{extra}}}",
        "# Режим «только TUN»: включается параметром tun.",
        "{{{tun}}}",
    ]
    return HEADER + "\n" + "\n".join(body) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    text = build()
    old = open(OUT, encoding="utf-8").read() if os.path.isfile(OUT) else ""
    if old == text:
        print(f"{OUT} актуален.")
        return 0
    if args.check:
        print(f"{OUT} устарел: python github_actions/build_vpn_module.py")
        return 1
    with open(OUT, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    print(f"{OUT} обновлён.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
