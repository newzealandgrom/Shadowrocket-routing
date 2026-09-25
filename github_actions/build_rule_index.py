#!/usr/bin/env python3
"""
Сборка индекса правил для страницы проверки http://sr.test (modules/Service-Check-RU.module).

Запуск:
    python github_actions/build_rule_index.py           # пересобрать Script/rule-index/
    python github_actions/build_rule_index.py --check   # exit 1, если индекс устарел

Зачем индекс. Страница показывает, по какому правилу SR_RU.conf пойдёт введённый адрес. Скрипт работает
внутри сетевого расширения iOS, у которого лимит памяти около 50 МБ, а reject.list и domains_refilter.list
вместе весят около 8 МБ. Поэтому скрипт не скачивает списки целиком, а берёт из индекса только нужные части:

  manifest.json   списки в том виде, как на них ссылается конфиг, и параметры разбиения;
  d/XX.txt        правила DOMAIN и DOMAIN-SUFFIX. Часть выбирается по FNV-1a от ключа: двух последних меток
                  домена правила. Для ключей, под которыми больше SPLIT_DOMAIN_KEY правил (com.br, co.uk и
                  т.п., список в manifest.json), правила с тремя и больше метками берут ключом три последние
                  метки. Поэтому для адреса нужны не больше трёх частей: по зоне, по двум и по трём
                  последним меткам адреса;
  ip4/A.B.C.D_N.txt
                  IPv4-подсети IP-CIDR. Адресное пространство делится на блоки /5, а блок, в котором больше
                  IP4_PART_LIMIT подсетей, делится на 8 блоков поменьше, до /24. Листья этого дерева
                  перечислены в manifest.json вместе с числом подсетей; файл есть только у непустых листьев.
                  Для адреса нужна одна часть: лист, в который он попадает;
  ip6.txt         подсети IP-CIDR6;
  other.txt       остальные правила: DOMAIN-KEYWORD, DOMAIN-WILDCARD, DST-PORT, IP-ASN, USER-AGENT и т.д.

Строка любой части начинается с номера списка из manifest.json и табуляции. В d/ перед точным доменом
(DOMAIN) стоит «=». В ip4/ и ip6.txt после подсети через табуляцию стоит «n», если у правила есть
no-resolve. В other.txt после номера списка идёт исходная строка правила.

Индексируются все списки из lists/, на которые ссылаются RULE-SET и DOMAIN-SET в SR_RU.conf. Хэш и правило
выбора частей повторяет Script/service-check.js: меняя одно, меняйте и другое.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from validate_lists import REPO_LISTS_PREFIX, parse_rule_line  # noqa: E402

CONF = "SR_RU.conf"
LISTS = "lists"
OUT = "Script/rule-index"

DOMAIN_SHARDS = 128
SPLIT_DOMAIN_KEY = 1000
IP4_ROOT_PREFIX = 5
IP4_PART_LIMIT = 1500
IP4_MAX_PREFIX = 24
FORMAT = 1


def fnv1a(text: str) -> int:
    h = 0x811C9DC5
    for byte in text.encode("utf-8"):
        h ^= byte
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


def shard_key(domain: str, split_keys: set[str]) -> str:
    """Две последние метки домена, для разбитых ключей три.

    Все суффиксы адреса a.b.example.com с двумя и более метками дают один и тот же ключ example.com,
    поэтому правило, подходящее адресу, всегда лежит в части по ключу адреса или по его зоне."""
    labels = domain.split(".")
    key = ".".join(labels[-2:])
    if key in split_keys and len(labels) >= 3:
        return ".".join(labels[-3:])
    return key


def domain_shard(domain: str, split_keys: set[str]) -> str:
    return f"{fnv1a(shard_key(domain, split_keys)) % DOMAIN_SHARDS:02x}"


def ip4_leaves(nets: list[tuple[int, ipaddress.IPv4Network, str]]):
    """[(блок, [(номер списка, подсеть, запись)])]: листья дерева блоков, покрывающие всё пространство IPv4."""
    leaves = []

    def split(block: ipaddress.IPv4Network, items) -> None:
        if len(items) > IP4_PART_LIMIT and block.prefixlen < IP4_MAX_PREFIX:
            for sub in block.subnets(new_prefix=min(block.prefixlen + 3, IP4_MAX_PREFIX)):
                split(sub, [it for it in items if it[1].overlaps(sub)])
        else:
            leaves.append((block, items))

    for root in ipaddress.ip_network("0.0.0.0/0").subnets(new_prefix=IP4_ROOT_PREFIX):
        split(root, [it for it in nets if it[1].overlaps(root)])
    return leaves


def conf_sets() -> list[tuple[str, str]]:
    """[(тип, url)] для RULE-SET и DOMAIN-SET из секции [Rule], в порядке конфига, без повторов."""
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    section = ""
    for lineno, line in enumerate(open(CONF, encoding="utf-8").read().split("\n"), 1):
        s = line.strip()
        if s.startswith("[") and s.endswith("]"):
            section = s[1:-1].strip().lower()
            continue
        if section != "rule":
            continue
        rule = parse_rule_line(CONF, lineno, line, in_list_file=False)
        if rule is None or rule.type not in ("RULE-SET", "DOMAIN-SET"):
            continue
        if rule.value.startswith(REPO_LISTS_PREFIX) and rule.value not in seen:
            seen.add(rule.value)
            out.append((rule.type, rule.value))
    return out


def build() -> dict[str, str]:
    """{путь внутри OUT: содержимое}."""
    domains: list[tuple[int, str]] = []  # (номер списка, запись d/)
    ip4: list[tuple[int, ipaddress.IPv4Network, str]] = []
    ip6_lines: list[tuple[int, str]] = []
    other_lines: list[tuple[int, str]] = []
    lists = []

    for list_id, (set_type, url) in enumerate(conf_sets()):
        name = url[len(REPO_LISTS_PREFIX):]
        path = os.path.join(LISTS, name)
        counts: dict[str, int] = defaultdict(int)
        cidr_resolve = 0
        for lineno, line in enumerate(open(path, encoding="utf-8").read().split("\n"), 1):
            if set_type == "DOMAIN-SET":
                s = line.strip().lower()
                if not s or s.startswith("#"):
                    continue
                if s.startswith("."):
                    domains.append((list_id, s[1:]))
                    counts["DOMAIN-SUFFIX"] += 1
                else:
                    domains.append((list_id, "=" + s))
                    counts["DOMAIN"] += 1
                continue
            rule = parse_rule_line(path, lineno, line)
            if rule is None:
                continue
            counts[rule.type] += 1
            if rule.type in ("DOMAIN", "DOMAIN-SUFFIX"):
                value = rule.value.strip().lower().strip(".")
                domains.append((list_id, ("=" if rule.type == "DOMAIN" else "") + value))
            elif rule.type in ("IP-CIDR", "IP-CIDR6"):
                net = ipaddress.ip_network(rule.value.strip(), strict=False)
                no_resolve = "no-resolve" in rule.options
                if not no_resolve:
                    cidr_resolve += 1
                entry = str(net) + ("\tn" if no_resolve else "")
                if net.version == 4:
                    ip4.append((list_id, net, entry))
                else:
                    ip6_lines.append((list_id, entry))
            else:
                other_lines.append((list_id, re.sub(r"\s+", " ", line.strip())))
        lists.append({
            "name": name,
            "type": set_type,
            "url": url,
            "rules": dict(sorted(counts.items())),
            "cidrResolve": cidr_resolve,
        })

    key_counts: dict[str, int] = defaultdict(int)
    for _list_id, entry in domains:
        key_counts[shard_key(entry.lstrip("="), set())] += 1
    split_keys = {key for key, count in key_counts.items() if count > SPLIT_DOMAIN_KEY}
    domain_parts: dict[str, list[tuple[int, str]]] = defaultdict(list)
    for list_id, entry in domains:
        domain_parts[domain_shard(entry.lstrip("="), split_keys)].append((list_id, entry))

    leaves = ip4_leaves(ip4)

    def render(lines: list[tuple[int, str]]) -> str:
        return "".join(f"{list_id}\t{entry}\n" for list_id, entry in sorted(set(lines)))

    files: dict[str, str] = {}
    for part in range(DOMAIN_SHARDS):
        files[f"d/{part:02x}.txt"] = render(domain_parts.get(f"{part:02x}", []))
    for block, items in leaves:
        if items:
            files[f"ip4/{block.network_address}_{block.prefixlen}.txt"] = render([(i, e) for i, _n, e in items])
    files["ip6.txt"] = render(ip6_lines)
    files["other.txt"] = render(other_lines)
    manifest = {
        "format": FORMAT,
        "config": CONF,
        "domainShards": DOMAIN_SHARDS,
        "splitKeys": sorted(split_keys),
        "ip4Parts": [[str(block), len(set((i, e) for i, _n, e in items))] for block, items in leaves],
        "lists": lists,
    }
    files["manifest.json"] = json.dumps(manifest, ensure_ascii=False, indent=1) + "\n"
    return files


def existing() -> dict[str, str]:
    out: dict[str, str] = {}
    if not os.path.isdir(OUT):
        return out
    for root, _dirs, names in os.walk(OUT):
        for name in names:
            full = os.path.join(root, name)
            rel = os.path.relpath(full, OUT).replace(os.sep, "/")
            out[rel] = open(full, encoding="utf-8").read()
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    new = build()
    old = existing()
    if new == old:
        print(f"{OUT} актуален.")
        return 0
    if args.check:
        changed = sorted(set(new) ^ set(old) | {p for p in new.keys() & old.keys() if new[p] != old[p]})
        print(f"{OUT} устарел ({len(changed)} файлов): python github_actions/build_rule_index.py")
        return 1
    for rel in old.keys() - new.keys():
        os.remove(os.path.join(OUT, rel))
    for rel, text in new.items():
        full = os.path.join(OUT, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        if old.get(rel) != text:
            with open(full, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(text)
    total = sum(len(t.encode("utf-8")) for t in new.values())
    print(f"{OUT} обновлён: {len(new)} файлов, {total / 1024 / 1024:.1f} МБ.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
