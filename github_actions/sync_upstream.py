#!/usr/bin/env python3
"""
Синхронизация списков в lists/ с их upstream-источниками.

Запуск:
    python github_actions/sync_upstream.py                  # обновить все списки из SOURCES
    python github_actions/sync_upstream.py Google.list      # только указанные
    python github_actions/sync_upstream.py --dry-run        # показать, что изменилось бы, не записывая

Для каждого списка из SOURCES:
  1. скачивается upstream-файл (или несколько, если url — список: они склеиваются);
  2. конвертируется в формат Shadowrocket (DOMAIN-SUFFIX,... / IP-CIDR,...,no-resolve);
  3. убираются типы правил из drop_types (если заданы);
  4. применяются локальные правки из lists/overrides/<имя>.exclude (что выкинуть)
     и lists/overrides/<имя>.append (что добавить) — по одному правилу на строку,
     комментарии через #;
  5. результат нормализуется (normalize_lists.py: нижний регистр, дубли, перекрытые записи);
  6. файл перезаписывается только если набор правил изменился.

Списки, которых нет в SOURCES (direct.list, proxy.list, reject.list, domains_banking.list,
domains_community.list, voice_ports.list, meta_ips.list, telegram_ips.list, discord.list,
TikTok.list), ведутся вручную и скриптом не трогаются.
"""
from __future__ import annotations

import argparse
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from normalize_lists import normalize_rule, normalize_text  # noqa: E402
from validate_lists import ALL_TYPES, CONF_ONLY_TYPES, parse_rule_line  # noqa: E402

BM7 = "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/"
REFILTER = "https://raw.githubusercontent.com/1andrevich/Re-filter-lists/main/"
METACUBEX = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/"
V2FLY = "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/"

# format:
#   shadowrocket — файл уже в формате Shadowrocket/Surge (берётся как есть);
#   domains      — по одному домену в строке -> DOMAIN-SUFFIX,<домен>;
#   cidrs        — по одной сети/адресу в строке -> IP-CIDR,<сеть>,no-resolve;
#   clash-domains — формат MetaCubeX/Clash: «+.example.com» -> DOMAIN-SUFFIX, «example.com» -> DOMAIN;
#   v2fly        — формат v2fly domain-list-community: «domain:x» -> DOMAIN-SUFFIX, «full:x» -> DOMAIN,
#                  «keyword:x» -> DOMAIN-KEYWORD; regexp: и include: пропускаются.
SOURCES: dict[str, dict] = {
    "Facebook.list": {"url": BM7 + "Facebook/Facebook.list", "format": "shadowrocket"},
    "GitHub.list": {"url": BM7 + "GitHub/GitHub.list", "format": "shadowrocket"},
    "Google.list": {"url": BM7 + "Google/Google.list", "format": "shadowrocket"},
    "OpenAI.list": {"url": BM7 + "OpenAI/OpenAI.list", "format": "shadowrocket"},
    "Telegram.list": {"url": BM7 + "Telegram/Telegram.list", "format": "shadowrocket"},
    "Twitter.list": {"url": BM7 + "Twitter/Twitter.list", "format": "shadowrocket"},
    "YouTube.list": {"url": BM7 + "YouTube/YouTube.list", "format": "shadowrocket"},
    # В Shadowrocket-версии Apple.list у blackmatrix7 только IP-подсети, USER-AGENT и ключевые слова;
    # доменные правила лежат в Apple/Apple_Domain.list, который здесь намеренно не подключён
    # (домены Apple попадают под GEOIP,RU / FINAL).
    "Apple.list": {"url": BM7 + "Apple/Apple.list", "format": "shadowrocket"},
    # community.lst — сайты, которые сами ограничивают доступ из РФ (Adobe, JetBrains, Intel...),
    # domains_all.lst — реестр заблокированного. Склеиваются в один список.
    "domains_refilter.list": {"url": [REFILTER + "community.lst", REFILTER + "domains_all.lst"],
                              "format": "domains"},
    "ips_refilter.list": {"url": REFILTER + "ipsum.lst", "format": "cidrs"},
    "domains_geo_detect.list": {"url": METACUBEX + "category-ip-geo-detect.list", "format": "clash-domains"},
    "private.list": {"url": V2FLY + "private", "format": "v2fly"},
}

UA = "Shadowrocket-routing sync (https://github.com/newzealandgrom/Shadowrocket-routing)"
KEEP_HEADER_RE = re.compile(r"^#\s*(NAME|AUTHOR|REPO|UPDATED|SOURCE)\s*:", re.I)


def fetch(url: str, retries: int = 3) -> str:
    ctx = ssl.create_default_context()
    last: Exception | None = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=60, context=ctx) as resp:
                raw = resp.read()
            return raw.decode("utf-8-sig")
        except (urllib.error.URLError, TimeoutError, OSError) as e:  # noqa: PERF203
            last = e
            time.sleep(2 * (attempt + 1))
    raise RuntimeError(f"не удалось скачать {url}: {last}")


def convert(text: str, fmt: str) -> tuple[list[str], list[str]]:
    """Возвращает (строки заголовка-комментария из upstream, строки правил)."""
    header: list[str] = []
    rules: list[str] = []
    for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        s = line.strip()
        if not s:
            continue
        if s.startswith("#") or s.startswith("//"):
            if KEEP_HEADER_RE.match(s):
                header.append(s)
            continue
        if fmt == "shadowrocket":
            rules.append(s)
        elif fmt == "domains":
            rules.append(f"DOMAIN-SUFFIX,{s.lower()}")
        elif fmt == "cidrs":
            rules.append(f"IP-CIDR,{s},no-resolve")
        elif fmt == "clash-domains":
            if s.startswith("+."):
                rules.append(f"DOMAIN-SUFFIX,{s[2:].lower()}")
            elif s.startswith("*."):
                rules.append(f"DOMAIN-SUFFIX,{s[2:].lower()}")
            elif "," in s:
                rules.append(s)
            else:
                rules.append(f"DOMAIN,{s.lower()}")
        elif fmt == "v2fly":
            s = s.split("#", 1)[0].split("@", 1)[0].strip()
            if not s:
                continue
            kind, _, val = s.partition(":")
            if not _:
                kind, val = "domain", s
            val = val.strip().lower()
            if kind == "domain":
                rules.append(f"DOMAIN-SUFFIX,{val}")
            elif kind == "full":
                rules.append(f"DOMAIN,{val}")
            elif kind == "keyword":
                rules.append(f"DOMAIN-KEYWORD,{val}")
            # regexp:, include: — не поддерживаются в RULE-SET, пропускаем
        else:
            raise ValueError(f"неизвестный формат {fmt}")
    return header, rules


def rule_key(line: str) -> tuple[str, str] | None:
    """Ключ правила в каноническом виде (нижний регистр, каноническая сеть), чтобы
    exclude-записи совпадали с upstream независимо от регистра."""
    r = parse_rule_line("", 0, line)
    return normalize_rule(r).key if r else None


def load_override(path: str) -> list[str]:
    """Строки override-файла; неверная строка (без типа правила и т.п.) — ошибка, а не тихий пропуск."""
    if not os.path.isfile(path):
        return []
    out = []
    for lineno, line in enumerate(open(path, encoding="utf-8"), 1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        r = parse_rule_line(path, lineno, s)
        if r is None or not r.value or r.type not in ALL_TYPES - CONF_ONLY_TYPES:
            raise ValueError(f"{path}:{lineno}: ожидается правило вида ТИП,значение (например DOMAIN-SUFFIX,example.com), получено «{s}»")
        out.append(s)
    return out


def rules_of(text: str) -> list[str]:
    return [l.strip() for l in text.split("\n") if l.strip() and not l.lstrip().startswith(("#", "//"))]


def build(name: str, spec: dict, lists_dir: str) -> tuple[str, dict]:
    urls = spec["url"] if isinstance(spec["url"], list) else [spec["url"]]
    header: list[str] = []
    rules: list[str] = []
    for url in urls:
        h, r = convert(fetch(url), spec["format"])
        header += [x for x in h if x not in header]
        rules += r
    stats = {"upstream": len(rules)}

    drop = {t.upper() for t in spec.get("drop_types", [])}
    if drop:
        rules = [r for r in rules if r.split(",", 1)[0].strip().upper() not in drop]
        stats["dropped_types"] = stats["upstream"] - len(rules)

    ov_dir = os.path.join(lists_dir, "overrides")
    exclude = {rule_key(r) for r in load_override(os.path.join(ov_dir, name.replace(".list", ".exclude")))}
    exclude.discard(None)
    if exclude:
        before = len(rules)
        rules = [r for r in rules if rule_key(r) not in exclude]
        stats["excluded"] = before - len(rules)
    append = load_override(os.path.join(ov_dir, name.replace(".list", ".append")))
    if append:
        rules.extend(append)
        stats["appended"] = len(append)

    body = "\n".join(rules) + "\n"
    norm_stats = {"chars": 0, "comments_moved": 0, "rewritten": 0, "duplicates": 0, "covered": 0}
    body = normalize_text(name, body, norm_stats)
    final_rules = rules_of(body)
    stats["duplicates"] = norm_stats["duplicates"]
    stats["covered"] = norm_stats["covered"]
    stats["total"] = len(final_rules)

    head = [f"# NAME: {name}"]
    head += [h for h in header if not re.match(r"^#\s*NAME\s*:", h, re.I)]
    if not any(re.match(r"^#\s*SOURCE\s*:", h, re.I) for h in header):
        head += [f"# SOURCE: {u}" for u in urls]
    if drop:
        head.append(f"# DROPPED-TYPES: {', '.join(sorted(drop))}")
    if exclude or append:
        head.append(f"# OVERRIDES: lists/overrides/{name.replace('.list', '')}.exclude / .append")
    head.append("# Генерируется скриптом github_actions/sync_upstream.py, правки вносите в overrides.")
    head.append(f"# TOTAL: {len(final_rules)}")
    return "\n".join(head) + "\n" + body, stats


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("names", nargs="*", help="имена списков (по умолчанию все из SOURCES)")
    ap.add_argument("--lists", default="lists")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--force", action="store_true",
                    help="записать, даже если список опустел или сократился более чем вдвое")
    args = ap.parse_args()

    names = args.names or list(SOURCES)
    failed = 0
    changed = 0
    for name in names:
        spec = SOURCES.get(name)
        if not spec:
            print(f"{name}: нет в SOURCES, пропущен")
            continue
        path = os.path.join(args.lists, name)
        try:
            new_text, stats = build(name, spec, args.lists)
        except Exception as e:  # noqa: BLE001
            print(f"{name}: ОШИБКА: {e}")
            failed += 1
            continue
        old_text = open(path, encoding="utf-8").read() if os.path.isfile(path) else ""
        old_rules = rules_of(old_text)
        new_rules = rules_of(new_text)
        detail = ", ".join(f"{k}={v}" for k, v in stats.items())
        # Защита от пустого/обрезанного ответа upstream (HTTP 200 с неполным телом).
        if not args.force and (not new_rules or (old_rules and len(new_rules) < 0.5 * len(old_rules))):
            print(f"{name}: ОШИБКА: upstream дал {len(new_rules)} правил вместо {len(old_rules)} — похоже на обрезанный "
                  f"ответ, файл не тронут (--force, чтобы записать; {detail})")
            failed += 1
            continue
        if old_rules == new_rules and old_text == new_text:
            print(f"{name}: без изменений ({detail})")
            continue
        added = len(set(new_rules) - set(old_rules))
        removed = len(set(old_rules) - set(new_rules))
        print(f"{name}: {len(old_rules)} -> {len(new_rules)} правил (+{added}/-{removed}; {detail})")
        changed += 1
        if not args.dry_run:
            with open(path, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(new_text)
    print()
    print(f"Изменено: {changed}, ошибок: {failed}" + (" (dry-run, файлы не записаны)" if args.dry_run else ""))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
