#!/usr/bin/env python3
"""
Приведение списков правил Shadowrocket к каноническому виду (правит файлы на месте).

Запуск:
    python github_actions/normalize_lists.py                 # все lists/*.list
    python github_actions/normalize_lists.py lists/direct.list lists/proxy.list
    python github_actions/normalize_lists.py --check         # только проверить, exit 1 если есть что менять

Что делает (порядок строк, комментарии и пустые строки сохраняются):
  * BOM и CRLF -> LF, пробелы в конце строк убираются;
  * невидимые символы (U+200B и т.п.) удаляются, типографские тире -> «-»;
  * inline-комментарий `RULE # текст` выносится отдельной строкой `# текст` над правилом;
  * тип правила и значения доменов/IP/портов -> нижний регистр (USER-AGENT, URL-REGEX, PROTOCOL не трогаются);
  * IP/CIDR -> каноническая запись сети (1.2.3.4/24 -> 1.2.3.0/24);
  * точные дубликаты внутри файла удаляются (остаётся первое вхождение);
  * записи, перекрытые в том же файле родительским DOMAIN-SUFFIX или более широкой подсетью, удаляются.
"""
from __future__ import annotations

import argparse
import ipaddress
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from validate_lists import (  # noqa: E402
    DASH_CHARS, DOMAIN_TYPES, INVISIBLE_CHARS, IP_TYPES, LOGIC_TYPES, PORT_TYPES,
    Rule, parent_suffixes, parse_rule_line,
)

LOWERCASE_TYPES = DOMAIN_TYPES | IP_TYPES | PORT_TYPES | {"IP-ASN", "DOMAIN-WILDCARD"}


def clean_chars(line: str) -> str:
    for ch in INVISIBLE_CHARS:
        line = line.replace(ch, "")
    if not line.lstrip().startswith(("#", "//", ";")):
        for ch in DASH_CHARS:
            line = line.replace(ch, "-")
    return line.rstrip()


def render(rule: Rule) -> str:
    return ",".join([rule.type, rule.value, *rule.options]) if rule.value or rule.options else rule.type


def normalize_rule(rule: Rule) -> Rule:
    rtype = rule.type
    value = rule.value
    if rtype in LOWERCASE_TYPES:
        value = value.lower()
    if rtype in IP_TYPES:
        try:
            value = str(ipaddress.ip_network(value, strict=False))
        except ValueError:
            pass
    if rtype == "GEOIP":
        value = value.upper()
    options = [o.lower() if o.lower() in {"no-resolve", "pre-matching", "extended-matching", "force-remote-dns"} else o
               for o in rule.options]
    return Rule(rule.file, rule.line, rule.raw, rtype, value, options, rule.comment)


def normalize_text(path: str, text: str, stats: dict[str, int]) -> str:
    text = text.lstrip("﻿").replace("\r\n", "\n").replace("\r", "\n")
    lines = text.split("\n")
    entries: list[tuple[str, str | Rule]] = []  # ("text", line) | ("rule", Rule)
    for lineno, line in enumerate(lines, 1):
        cleaned = clean_chars(line)
        if cleaned != line.rstrip():
            stats["chars"] += 1
        rule = parse_rule_line(path, lineno, cleaned)
        if rule is None:
            entries.append(("text", cleaned))
            continue
        if rule.comment:
            entries.append(("text", rule.comment))
            stats["comments_moved"] += 1
        norm = normalize_rule(rule)
        if render(norm) != cleaned.strip():
            stats["rewritten"] += 1
        entries.append(("rule", norm))

    # Дубликаты.
    seen: set[tuple] = set()
    deduped: list[tuple[str, str | Rule]] = []
    for kind, item in entries:
        if kind == "rule":
            k = (item.type, item.value, tuple(item.options))
            if k in seen:
                stats["duplicates"] += 1
                continue
            seen.add(k)
        deduped.append((kind, item))

    # Перекрытые записи.
    suffixes = {(r.value, tuple(r.options)) for k, r in deduped if k == "rule" and r.type == "DOMAIN-SUFFIX"}
    nets = set()
    for k, r in deduped:
        if k == "rule" and r.type in IP_TYPES:
            try:
                nets.add((r.type, ipaddress.ip_network(r.value), tuple(r.options)))
            except ValueError:
                pass

    def covered(r: Rule) -> bool:
        if r.type in {"DOMAIN", "DOMAIN-SUFFIX"}:
            cands = list(parent_suffixes(r.value))
            if r.type == "DOMAIN":
                cands.insert(0, r.value)
            return any((p, tuple(r.options)) in suffixes for p in cands)
        if r.type in IP_TYPES:
            try:
                net = ipaddress.ip_network(r.value)
            except ValueError:
                return False
            parent = net
            while parent.prefixlen > 0:
                parent = parent.supernet()
                if (r.type, parent, tuple(r.options)) in nets:
                    return True
        return False

    out: list[str] = []
    for kind, item in deduped:
        if kind == "text":
            out.append(item)
            continue
        if covered(item):
            stats["covered"] += 1
            continue
        out.append(render(item))

    result = "\n".join(out)
    # Ровно один перевод строки в конце файла, без пустых строк в самом конце.
    result = result.rstrip("\n") + "\n"
    return result


def process(path: str, check_only: bool) -> bool:
    """Возвращает True, если файл изменился (или должен был бы измениться в --check)."""
    raw = open(path, "rb").read()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as e:
        print(f"{path}: пропущен, не UTF-8 ({e})")
        return False
    stats = {"chars": 0, "comments_moved": 0, "rewritten": 0, "duplicates": 0, "covered": 0}
    new = normalize_text(path, text, stats)
    if new == text:
        return False
    before = sum(1 for l in text.split("\n") if l.strip() and not l.lstrip().startswith(("#", "//", ";")))
    after = sum(1 for l in new.split("\n") if l.strip() and not l.lstrip().startswith(("#", "//", ";")))
    detail = ", ".join(f"{k}={v}" for k, v in stats.items() if v)
    print(f"{path}: правил {before} -> {after} ({detail or 'только форматирование'})")
    if not check_only:
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(new)
    return True


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="*", help="файлы списков (по умолчанию все lists/*.list)")
    ap.add_argument("--lists", default="lists")
    ap.add_argument("--check", action="store_true", help="ничего не менять, exit 1 если есть что нормализовать")
    args = ap.parse_args()

    files = args.files or sorted(os.path.join(args.lists, f) for f in os.listdir(args.lists) if f.endswith(".list"))
    changed = [f for f in files if process(f, args.check)]
    if not changed:
        print("Все файлы уже в каноническом виде.")
        return 0
    if args.check:
        print(f"{len(changed)} файл(ов) требуют нормализации: python github_actions/normalize_lists.py")
        return 1
    print(f"Изменено файлов: {len(changed)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
