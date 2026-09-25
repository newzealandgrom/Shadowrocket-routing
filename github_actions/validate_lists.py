#!/usr/bin/env python3
"""
Валидация списков правил Shadowrocket (lists/*.list) и главного конфига (SR_RU.conf).

Запуск:
    python github_actions/validate_lists.py                 # проверить всё
    python github_actions/validate_lists.py --conf SR_RU.conf --lists lists

Код возврата 1, если есть хотя бы одна ОШИБКА. Предупреждения на код возврата не влияют.

ОШИБКИ (ломают правило или конфиг):
  * неизвестный тип правила, RULE-SET/FINAL внутри файла списка;
  * невидимые символы (U+200B и т.п.), типографские тире, не-ASCII в самом правиле
    (кириллические домены должны быть в punycode), CRLF, BOM;
  * wildcard (*) в DOMAIN / DOMAIN-SUFFIX, заглавные буквы в домене, некорректный домен;
  * некорректный IP/CIDR, порт или диапазон портов, ASN, GEOIP;
  * точные дубликаты внутри одного файла;
  * одна и та же запись в списках с политиками DIRECT и PROXY (реальный конфликт маршрутизации);
  * RULE-SET в конфиге ссылается на файл, которого нет в lists/.

ПРЕДУПРЕЖДЕНИЯ (работает, но стоит поправить):
  * запись перекрыта родительским суффиксом / более широкой подсетью в том же файле;
  * запись есть и в reject.list, и в другом списке (reject.list стоит выше и побеждает);
  * одинаковые записи в двух списках с одной политикой (лишнее);
  * политика (PROXY/DIRECT/...) внутри файла списка: её задаёт RULE-SET в конфиге;
  * файл в lists/, на который конфиг не ссылается; RULE-SET через github.com/.../raw/ (редирект).
"""
from __future__ import annotations

import argparse
import ipaddress
import os
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from urllib.parse import urlparse

DOMAIN_TYPES = {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD"}
IP_TYPES = {"IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR"}
PORT_TYPES = {"DST-PORT", "SRC-PORT"}
LOGIC_TYPES = {"AND", "OR", "NOT"}
SIMPLE_TYPES = {"IP-ASN", "GEOIP", "USER-AGENT", "URL-REGEX", "PROTOCOL", "PROCESS-NAME"}
CONF_ONLY_TYPES = {"RULE-SET", "DOMAIN-SET", "SCRIPT", "FINAL"}
ALL_TYPES = DOMAIN_TYPES | IP_TYPES | PORT_TYPES | LOGIC_TYPES | SIMPLE_TYPES | CONF_ONLY_TYPES

POLICIES = {
    "DIRECT", "PROXY", "REJECT", "REJECT-DROP", "REJECT-NO-DROP", "REJECT-TINYGIF",
    "REJECT-DICT", "REJECT-ARRAY", "REJECT-200", "REJECT-IMG",
}
RULE_OPTIONS = {"no-resolve", "pre-matching", "extended-matching", "force-remote-dns"}
PROTOCOLS = {"TCP", "UDP", "HTTP", "HTTPS", "ICMP", "QUIC"}

INVISIBLE_CHARS = {
    "​": "U+200B ZERO WIDTH SPACE",
    "‌": "U+200C ZERO WIDTH NON-JOINER",
    "‍": "U+200D ZERO WIDTH JOINER",
    "⁠": "U+2060 WORD JOINER",
    "﻿": "U+FEFF BOM",
    " ": "U+00A0 NO-BREAK SPACE",
    "­": "U+00AD SOFT HYPHEN",
}
DASH_CHARS = {
    "‐": "U+2010 HYPHEN", "‑": "U+2011 NON-BREAKING HYPHEN",
    "‒": "U+2012 FIGURE DASH", "–": "U+2013 EN DASH",
    "—": "U+2014 EM DASH", "−": "U+2212 MINUS SIGN",
}
DOMAIN_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
KEYWORD_RE = re.compile(r"^[a-z0-9.\-_]+$")

REPO_LISTS_PREFIX = "https://raw.githubusercontent.com/newzealandgrom/Shadowrocket-routing/refs/heads/master/lists/"


@dataclass
class Issue:
    level: str          # "error" | "warning"
    file: str
    line: int           # 0 = файл целиком
    message: str


@dataclass
class Rule:
    file: str
    line: int
    raw: str
    type: str
    value: str
    options: list[str] = field(default_factory=list)
    comment: str = ""

    @property
    def key(self) -> tuple[str, str]:
        """Ключ для сравнения между файлами: тип + нормализованное значение."""
        return (self.type, canonical_value(self.type, self.value))


def canonical_value(rtype: str, value: str) -> str:
    if rtype in IP_TYPES:
        try:
            return str(ipaddress.ip_network(value, strict=False))
        except ValueError:
            return value
    return value


# ----------------------------------------------------------------------------
# Разбор строк
# ----------------------------------------------------------------------------

def split_inline_comment(rtype: str, rest: str) -> tuple[str, str]:
    """`value,opts # comment` -> (`value,opts`, `comment`). Для URL-REGEX/USER-AGENT не трогаем."""
    if rtype in {"URL-REGEX", "USER-AGENT"}:
        return rest, ""
    m = re.search(r"\s(#|//)", rest)
    if m:
        return rest[: m.start()].rstrip(), rest[m.start():].strip()
    return rest, ""


def split_logic_rule(rest: str) -> tuple[str, list[str]]:
    """Для AND/OR/NOT значение — сбалансированная скобочная группа, дальше опции/политика."""
    rest = rest.strip()
    if not rest.startswith("("):
        return rest, []
    depth = 0
    for i, ch in enumerate(rest):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                value = rest[: i + 1]
                tail = rest[i + 1:].strip()
                opts = [t.strip() for t in tail.split(",") if t.strip()]
                return value, opts
    return rest, []


def parse_rule_line(file: str, lineno: int, line: str) -> Rule | None:
    """Разобрать строку правила. Возвращает None для пустых строк и комментариев."""
    stripped = line.strip()
    if not stripped or stripped.startswith("#") or stripped.startswith("//") or stripped.startswith(";"):
        return None
    if "," not in stripped:
        return Rule(file, lineno, line, stripped.upper(), "")
    rtype, rest = stripped.split(",", 1)
    rtype = rtype.strip().upper()
    rest, comment = split_inline_comment(rtype, rest)
    if rtype in LOGIC_TYPES:
        value, opts = split_logic_rule(rest)
    elif rtype in {"URL-REGEX", "USER-AGENT"}:
        # Регулярка/UA могут содержать запятые: опции распознаём только по известным словам в хвосте.
        parts = [p.strip() for p in rest.split(",")]
        opts: list[str] = []
        while len(parts) > 1 and (parts[-1] in RULE_OPTIONS or parts[-1].upper() in POLICIES):
            opts.insert(0, parts.pop())
        value = ",".join(parts)
    else:
        parts = [p.strip() for p in rest.split(",")]
        value, opts = parts[0], parts[1:]
    return Rule(file, lineno, line, rtype, value, opts, comment)


# ----------------------------------------------------------------------------
# Проверки одного правила
# ----------------------------------------------------------------------------

def check_domain_value(rule: Rule, issues: list[Issue]) -> None:
    v = rule.value
    err = lambda msg: issues.append(Issue("error", rule.file, rule.line, msg))
    if not v:
        err(f"{rule.type}: пустое значение")
        return
    if "*" in v:
        err(f"{rule.type},{v}: wildcard (*) в доменном правиле недопустим, правило никогда не сработает")
        return
    if any(ord(c) > 127 for c in v):
        err(f"{rule.type},{v}: не-ASCII символы в домене; используйте punycode (xn--...)")
        return
    if v != v.lower():
        err(f"{rule.type},{v}: заглавные буквы в домене; приведите к нижнему регистру")
        return
    if rule.type == "DOMAIN-KEYWORD":
        if not KEYWORD_RE.match(v):
            err(f"DOMAIN-KEYWORD,{v}: недопустимые символы в ключевом слове")
        return
    if v.startswith(".") or v.endswith("."):
        err(f"{rule.type},{v}: домен не должен начинаться или заканчиваться точкой")
        return
    for label in v.split("."):
        if not DOMAIN_LABEL_RE.match(label):
            err(f"{rule.type},{v}: некорректная метка домена «{label}»")
            return


def check_ip_value(rule: Rule, issues: list[Issue]) -> None:
    try:
        net = ipaddress.ip_network(rule.value, strict=False)
    except ValueError:
        issues.append(Issue("error", rule.file, rule.line, f"{rule.type},{rule.value}: некорректный IP/CIDR"))
        return
    if rule.type == "IP-CIDR6" and net.version != 6:
        issues.append(Issue("error", rule.file, rule.line, f"IP-CIDR6,{rule.value}: это не IPv6-подсеть"))
    if str(net) != rule.value:
        issues.append(Issue("warning", rule.file, rule.line,
                            f"{rule.type},{rule.value}: в адресе выставлены биты хоста, каноническая запись {net}"))


def check_port_value(rule: Rule, issues: list[Issue]) -> None:
    v = rule.value
    ok = False
    if re.fullmatch(r"\d{1,5}", v):
        ok = 1 <= int(v) <= 65535
    elif re.fullmatch(r"\d{1,5}-\d{1,5}", v):
        a, b = (int(x) for x in v.split("-"))
        ok = 1 <= a < b <= 65535
    if not ok:
        issues.append(Issue("error", rule.file, rule.line,
                            f"{rule.type},{v}: порт должен быть числом 1-65535 или диапазоном A-B (A<B) через обычный дефис"))


def check_rule(rule: Rule, issues: list[Issue], in_list_file: bool) -> None:
    if rule.type not in ALL_TYPES:
        issues.append(Issue("error", rule.file, rule.line, f"неизвестный тип правила «{rule.type}»"))
        return
    if in_list_file and rule.type in CONF_ONLY_TYPES:
        issues.append(Issue("error", rule.file, rule.line, f"{rule.type} нельзя использовать внутри файла списка"))
        return

    if rule.type in DOMAIN_TYPES:
        check_domain_value(rule, issues)
    elif rule.type in IP_TYPES:
        check_ip_value(rule, issues)
    elif rule.type in PORT_TYPES:
        check_port_value(rule, issues)
    elif rule.type == "IP-ASN":
        if not re.fullmatch(r"\d+", rule.value):
            issues.append(Issue("error", rule.file, rule.line, f"IP-ASN,{rule.value}: ASN должен быть числом"))
    elif rule.type == "GEOIP":
        if not re.fullmatch(r"[A-Za-z]{2}", rule.value):
            issues.append(Issue("error", rule.file, rule.line, f"GEOIP,{rule.value}: ожидается двухбуквенный код страны"))
    elif rule.type == "PROTOCOL":
        if rule.value.upper() not in PROTOCOLS:
            issues.append(Issue("warning", rule.file, rule.line, f"PROTOCOL,{rule.value}: нестандартный протокол"))
    elif rule.type == "URL-REGEX":
        try:
            re.compile(rule.value)
        except re.error as e:
            issues.append(Issue("warning", rule.file, rule.line, f"URL-REGEX: регулярное выражение не компилируется в Python ({e}); проверьте вручную"))
    elif rule.type in {"USER-AGENT", "PROCESS-NAME"} and not rule.value:
        issues.append(Issue("error", rule.file, rule.line, f"{rule.type}: пустое значение"))
    elif rule.type in LOGIC_TYPES:
        if not (rule.value.startswith("(") and rule.value.endswith(")")):
            issues.append(Issue("error", rule.file, rule.line, f"{rule.type}: ожидается скобочная группа ((RULE,value),(RULE,value))"))

    # Хвост правила: опции и (в конфиге) политика.
    for i, opt in enumerate(rule.options):
        if opt in RULE_OPTIONS:
            if opt == "no-resolve" and rule.type not in IP_TYPES | {"IP-ASN", "GEOIP"} | LOGIC_TYPES:
                issues.append(Issue("warning", rule.file, rule.line, f"опция no-resolve не имеет смысла для {rule.type}"))
            continue
        if opt.upper() in POLICIES or (not in_list_file and i == 0):
            if in_list_file:
                issues.append(Issue("warning", rule.file, rule.line,
                                    f"политика «{opt}» внутри файла списка не нужна: её задаёт RULE-SET в конфиге"))
            continue
        issues.append(Issue("warning", rule.file, rule.line, f"неизвестная опция «{opt}»"))


# ----------------------------------------------------------------------------
# Проверка файла
# ----------------------------------------------------------------------------

def read_text(path: str, issues: list[Issue]) -> str | None:
    raw = open(path, "rb").read()
    if raw.startswith(b"\xef\xbb\xbf"):
        issues.append(Issue("error", path, 1, "файл начинается с UTF-8 BOM"))
        raw = raw[3:]
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as e:
        issues.append(Issue("error", path, 0, f"файл не в UTF-8: {e}"))
        return None
    if "\r" in text:
        issues.append(Issue("error", path, 0, "CRLF-переводы строк; нужен LF"))
        text = text.replace("\r\n", "\n").replace("\r", "\n")
    return text


def check_line_chars(path: str, lineno: int, line: str, issues: list[Issue]) -> None:
    for ch, name in INVISIBLE_CHARS.items():
        if ch in line:
            issues.append(Issue("error", path, lineno, f"невидимый символ {name}"))
    is_comment = line.lstrip().startswith(("#", "//", ";"))
    if is_comment:
        return
    for ch, name in DASH_CHARS.items():
        if ch in line:
            issues.append(Issue("error", path, lineno, f"типографское тире {name} вместо дефиса «-»"))
    if line != line.rstrip():
        issues.append(Issue("warning", path, lineno, "пробелы в конце строки"))


def parent_suffixes(domain: str):
    parts = domain.split(".")
    for i in range(1, len(parts)):
        yield ".".join(parts[i:])


def check_intra_file(path: str, rules: list[Rule], issues: list[Issue]) -> None:
    seen: dict[tuple, Rule] = {}
    for r in rules:
        k = (r.type, canonical_value(r.type, r.value), tuple(r.options))
        if k in seen:
            issues.append(Issue("error", path, r.line,
                                f"дубликат строки {seen[k].line}: {r.type},{r.value}"))
        else:
            seen[k] = r

    suffixes = {(r.value, tuple(r.options)) for r in rules if r.type == "DOMAIN-SUFFIX"}
    for r in rules:
        if r.type not in {"DOMAIN", "DOMAIN-SUFFIX"}:
            continue
        candidates = list(parent_suffixes(r.value))
        if r.type == "DOMAIN":
            candidates.insert(0, r.value)
        for p in candidates:
            if (p, tuple(r.options)) in suffixes:
                issues.append(Issue("warning", path, r.line,
                                    f"{r.type},{r.value} перекрыт DOMAIN-SUFFIX,{p} в этом же файле (лишняя запись)"))
                break

    nets: dict[tuple, Rule] = {}
    for r in rules:
        if r.type in IP_TYPES:
            try:
                nets[(r.type, ipaddress.ip_network(r.value, strict=False), tuple(r.options))] = r
            except ValueError:
                pass
    for (rtype, net, opts), r in nets.items():
        parent = net
        while parent.prefixlen > 0:
            parent = parent.supernet()
            if (rtype, parent, opts) in nets:
                issues.append(Issue("warning", path, r.line,
                                    f"{rtype},{r.value} входит в {parent} из этого же файла (лишняя запись)"))
                break


def check_list_file(path: str, issues: list[Issue]) -> list[Rule]:
    text = read_text(path, issues)
    if text is None:
        return []
    rules: list[Rule] = []
    for lineno, line in enumerate(text.split("\n"), 1):
        check_line_chars(path, lineno, line, issues)
        rule = parse_rule_line(path, lineno, line)
        if rule is None:
            continue
        check_rule(rule, issues, in_list_file=True)
        rules.append(rule)
    if not rules:
        issues.append(Issue("warning", path, 0, "в файле нет ни одного правила"))
    check_intra_file(path, rules, issues)
    return rules


# ----------------------------------------------------------------------------
# Конфиг
# ----------------------------------------------------------------------------

def check_conf(conf_path: str, lists_dir: str, issues: list[Issue]) -> dict[str, str]:
    """Возвращает {имя файла списка: политика} по RULE-SET из конфига."""
    policies: dict[str, str] = {}
    text = read_text(conf_path, issues)
    if text is None:
        return policies
    section = ""
    last_rule: Rule | None = None
    final_seen_at = 0
    for lineno, line in enumerate(text.split("\n"), 1):
        check_line_chars(conf_path, lineno, line, issues)
        s = line.strip()
        if s.startswith("[") and s.endswith("]"):
            section = s[1:-1].strip().lower()
            continue
        if section != "rule":
            continue
        rule = parse_rule_line(conf_path, lineno, line)
        if rule is None:
            continue
        if final_seen_at:
            issues.append(Issue("warning", conf_path, lineno, f"правило после FINAL (строка {final_seen_at}) никогда не сработает"))
        if rule.type == "FINAL":
            final_seen_at = lineno
            continue
        if rule.type == "RULE-SET" or rule.type == "DOMAIN-SET":
            url = rule.value
            policy = rule.options[0] if rule.options else ""
            if not policy:
                issues.append(Issue("error", conf_path, lineno, f"{rule.type} без политики"))
            u = urlparse(url)
            if u.scheme not in {"http", "https"}:
                issues.append(Issue("warning", conf_path, lineno, f"{rule.type}: локальный или нестандартный путь «{url}»"))
                continue
            if u.netloc == "github.com" and "/raw/" in u.path:
                issues.append(Issue("warning", conf_path, lineno,
                                    "ссылка через github.com/.../raw/ даёт 302-редирект; используйте raw.githubusercontent.com"))
            if url.startswith(REPO_LISTS_PREFIX):
                name = url[len(REPO_LISTS_PREFIX):]
                if not os.path.isfile(os.path.join(lists_dir, name)):
                    issues.append(Issue("error", conf_path, lineno, f"{rule.type} ссылается на отсутствующий файл lists/{name}"))
                else:
                    policies[name] = policy.upper()
            continue
        check_rule(rule, issues, in_list_file=False)
        if not rule.options:
            issues.append(Issue("error", conf_path, lineno, f"правило без политики: {s}"))
        last_rule = rule
    if section == "" and not policies:
        issues.append(Issue("error", conf_path, 0, "в конфиге нет секции [Rule]"))
    if not final_seen_at:
        issues.append(Issue("warning", conf_path, 0, "в секции [Rule] нет правила FINAL"))
    return policies


# ----------------------------------------------------------------------------
# Пересечения между файлами
# ----------------------------------------------------------------------------

def is_reject(policy: str) -> bool:
    return policy.startswith("REJECT")


def check_cross_file(all_rules: dict[str, list[Rule]], policies: dict[str, str], issues: list[Issue]) -> None:
    by_key: dict[tuple, list[Rule]] = defaultdict(list)
    for name, rules in all_rules.items():
        first_in_file: set[tuple] = set()
        for r in rules:
            if r.type in LOGIC_TYPES or r.type in {"USER-AGENT", "URL-REGEX"}:
                continue
            if r.key in first_in_file:
                continue
            first_in_file.add(r.key)
            by_key[r.key].append(r)

    for key, rules in sorted(by_key.items()):
        files = sorted({r.file for r in rules})
        if len(files) < 2:
            continue
        pols = {os.path.basename(f): policies.get(os.path.basename(f), "?") for f in files}
        where = ", ".join(f"{os.path.basename(r.file)}:{r.line}" for r in rules)
        rule_txt = f"{key[0]},{key[1]}"
        known = {p for p in pols.values() if p != "?"}
        non_reject = {p for p in known if not is_reject(p)}
        if "?" in pols.values():
            issues.append(Issue("warning", rules[0].file, rules[0].line,
                                f"{rule_txt} есть в нескольких списках ({where}), политика одного из них неизвестна (файл не подключён в конфиге)"))
        elif len(non_reject) > 1:
            issues.append(Issue("error", rules[0].file, rules[0].line,
                                f"КОНФЛИКТ: {rule_txt} в списках с разными политиками {dict(pols)} ({where}); победит тот, что выше в конфиге"))
        elif any(is_reject(p) for p in known) and non_reject:
            other = [f"{os.path.basename(r.file)}:{r.line}" for r in rules if not is_reject(policies.get(os.path.basename(r.file), ""))]
            issues.append(Issue("warning", rules[0].file, rules[0].line,
                                f"{rule_txt} блокируется reject-списком, запись в {', '.join(other)} не работает"))
        else:
            issues.append(Issue("warning", rules[0].file, rules[0].line,
                                f"{rule_txt} повторяется в списках с одной политикой ({where}); достаточно одного"))


# ----------------------------------------------------------------------------
# main
# ----------------------------------------------------------------------------

def emit(issue: Issue, gha: bool) -> None:
    loc = f"{issue.file}:{issue.line}" if issue.line else issue.file
    tag = "ОШИБКА" if issue.level == "error" else "предупреждение"
    print(f"{tag}: {loc}: {issue.message}")
    if gha:
        title = "validate_lists"
        line = f",line={issue.line}" if issue.line else ""
        msg = issue.message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        print(f"::{issue.level} file={issue.file}{line},title={title}::{msg}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--conf", default="SR_RU.conf")
    ap.add_argument("--lists", default="lists")
    ap.add_argument("--quiet-warnings", action="store_true", help="не печатать предупреждения")
    args = ap.parse_args()

    issues: list[Issue] = []
    policies: dict[str, str] = {}
    if os.path.isfile(args.conf):
        policies = check_conf(args.conf, args.lists, issues)
    else:
        issues.append(Issue("warning", args.conf, 0, "конфиг не найден, пересечения между списками не классифицируются"))

    all_rules: dict[str, list[Rule]] = {}
    list_files = sorted(f for f in os.listdir(args.lists) if f.endswith(".list"))
    for name in list_files:
        path = os.path.join(args.lists, name)
        all_rules[path] = check_list_file(path, issues)
        if policies and name not in policies:
            issues.append(Issue("warning", path, 0, f"файл не подключён ни одним RULE-SET в {args.conf}"))

    check_cross_file(all_rules, policies, issues)

    gha = bool(os.environ.get("GITHUB_ACTIONS"))
    errors = [i for i in issues if i.level == "error"]
    warnings = [i for i in issues if i.level == "warning"]
    for i in sorted(issues, key=lambda x: (x.level != "error", x.file, x.line)):
        if i.level == "warning" and args.quiet_warnings:
            continue
        emit(i, gha)

    total_rules = sum(len(r) for r in all_rules.values())
    print()
    print(f"Файлов: {len(list_files)}, правил: {total_rules}, ошибок: {len(errors)}, предупреждений: {len(warnings)}")
    if gha and os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as fh:
            fh.write(f"### validate_lists\n\n- файлов: {len(list_files)}\n- правил: {total_rules}\n"
                     f"- ошибок: **{len(errors)}**\n- предупреждений: {len(warnings)}\n")
    if errors:
        print("❌ Есть ошибки.")
        return 1
    print("✅ Ошибок нет.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
