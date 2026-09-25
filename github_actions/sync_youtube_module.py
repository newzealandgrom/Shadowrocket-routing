#!/usr/bin/env python3
"""
Сборка модулей YouTube из актуального YouTube Enhance (Maasea/sgmodule).

Запуск:
    python github_actions/sync_youtube_module.py            # обновить модули и скрипты
    python github_actions/sync_youtube_module.py --check    # только проверить, exit 1 если есть что обновить
    python github_actions/sync_youtube_module.py --ref <sha> # собрать из конкретного коммита Maasea

Зачем: скрипты Maasea и строки [Script] в модуле меняются вместе (в июле 2026 добавились перехваты
googlevideo.com/initplayback и youtubei/v1/log_event). Если обновить только скрипт, модуль перестаёт
резать часть рекламы. Поэтому генератор берёт модуль и скрипты из одного коммита Maasea (последнего,
который менял YouTube), кладёт скрипты в Script/ и ссылается на них с ?v=<коммит>, чтобы Shadowrocket
скачал новую версию сразу после обновления модуля.

Собираются два варианта:

  modules/YT-Premium-V1-RU.module — основной, без сторонних серверов.
      С июля 2026 YouTube отдаёт данные для запуска части роликов (вместе с рекламой) зашифрованными
      в ответе googlevideo.com/initplayback. Maasea расшифровывает их на своём сервере Cloudflare.
      Пока ключ не пойман, его же скрипт отвечает на initplayback пустым ответом, и приложение
      переходит на обычный youtubei/v1/player, где рекламу вырезает скрипт на телефоне. Основной
      вариант делает так всегда: [Map Local] с пустым ответом вместо перехвата initplayback,
      без перехвата log_event и без сбора ключей.

  modules/YT-Premium-Worker-RU.module — полная схема Maasea с его сервером
      init-stream.maasea.workers.dev. Сервер получает запрос запуска видео и ключ расшифровки.

В оба варианта добавлены правила блокировки QUIC для доменов YouTube (как у Maasea до июля 2026):
в отличие от Surge, Shadowrocket не блокирует QUIC для хостов из MITM сам, а по QUIC расшифровка
не работает. REJECT-NO-DROP отвечает «порт недоступен», и приложение сразу переходит на TCP
(такой вариант приводит руководство Shadowrocket: AND,((PROTOCOL,UDP),(DST-PORT,443)),REJECT-NO-DROP).

max-size задаётся явно (8 МиБ): что означают 0 и -1, Shadowrocket не документирует, а ответы
YouTube бывают больше лимита по умолчанию, и тогда скрипт пропускает их.

Скрипты Maasea распространяются по лицензии Apache-2.0.
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tempfile

UPSTREAM_GIT = "https://github.com/Maasea/sgmodule"
UPSTREAM_MODULE = "YouTube.Enhance.sgmodule"
UPSTREAM_SCRIPT_DIR = "Script/Youtube"
UPSTREAM_RAW_RE = re.compile(r"https://raw\.githubusercontent\.com/Maasea/sgmodule/[^/]+/Script/Youtube/([A-Za-z0-9._-]+\.js)")

OUT_SCRIPT_DIR = "Script"
OUR_RAW = "https://raw.githubusercontent.com/newzealandgrom/Shadowrocket-routing/refs/heads/master/Script/"

# Имена параметров Maasea -> наши. Неизвестный параметр остаётся с исходным именем (с предупреждением).
# Не переименовывайте ключи без необходимости: сохранённые пользователем значения привязаны к именам.
ARG_NAMES = {
    "屏蔽上传按钮": "blockUpload",
    "屏蔽选段按钮": "blockImmersive",
    "屏蔽Shorts按钮": "blockShorts",
    "字幕翻译语言": "captionLang",
    "歌词翻译语言": "lyricLang",
    "脚本执行引擎": "engine",
    "启用调试模式": "debug",
}
# Наши значения по умолчанию (перекрывают значения Maasea).
ARG_DEFAULTS = {
    "blockUpload": "true",
    "blockImmersive": "false",
    "blockShorts": "true",
    "captionLang": "off",
    "debug": "false",
}
ARG_DESC = {
    "blockUpload": "blockUpload: true — скрыть кнопку «Создать» (+) на нижней панели",
    "blockImmersive": "blockImmersive: true — скрыть вкладку «Сэмплы» в YouTube Music",
    "blockShorts": "blockShorts: true — скрыть вкладку Shorts",
    "captionLang": "captionLang: код языка для перевода субтитров (ru, en, uk…) или off, чтобы не переводить",
    "lyricLang": "lyricLang: код языка для перевода текстов песен или off",
    "engine": "engine: движок скриптов auto, jsc или webview",
    "debug": "debug: true — подробный журнал скриптов (для диагностики)",
}

VARIANTS = {
    "modules/YT-Premium-V1-RU.module": {
        "worker": False,
        "name": "YouTube Premium RU",
        "desc": "Убирает рекламу в YouTube и YouTube Music, включает фоновое воспроизведение. Всё обрабатывается "
                "на телефоне, без сторонних серверов. Нужен установленный и доверенный MITM-сертификат. "
                "Основан на YouTube Enhance (Maasea).",
    },
    "modules/YT-Premium-Worker-RU.module": {
        "worker": True,
        "name": "YouTube Premium RU (сервер Maasea)",
        "desc": "Полная схема YouTube Enhance (Maasea): часть запросов запуска видео вместе с ключом расшифровки "
                "уходит на сервер автора init-stream.maasea.workers.dev. Пробуйте, только если основной модуль "
                "пропускает рекламу. Не включайте вместе с основным. Нужен MITM-сертификат.",
    },
}

HEADER = """#!name={name}
#!desc={desc}
#!arguments={arguments}
#!arguments-desc={arguments_desc}
#!homepage=https://github.com/newzealandgrom/Shadowrocket-routing
# Источник: {git}, коммит {sha} ({date}), лицензия Apache-2.0.
# Файл генерирует github_actions/sync_youtube_module.py: правки вносите в генератор, а не сюда.
"""

# QUIC (HTTP/3) не расшифровывается. См. описание в начале файла.
EXTRA_RULES = [
    "# QUIC (HTTP/3) не расшифровывается: переводим YouTube на TCP, иначе скрипты не срабатывают",
    "AND,((DOMAIN-SUFFIX,googlevideo.com),(PROTOCOL,UDP)),REJECT-NO-DROP",
    "AND,((DOMAIN,youtubei.googleapis.com),(PROTOCOL,UDP)),REJECT-NO-DROP",
]

MAX_SIZE = "max-size=8388608"
MAX_SIZE_RE = re.compile(r"max-size=-?\d+")

# Пустой ответ на initplayback: то же, что отдаёт скрипт Maasea, когда ключа нет
# ($done({response:{status:200,headers:{"Content-Type":"text/plain"},body:new Uint8Array}})).
MAP_LOCAL_EMPTY = 'data-type=text data="" status-code=200'


def run(cmd: list[str], cwd: str | None = None) -> str:
    return subprocess.run(cmd, cwd=cwd, check=True, capture_output=True, text=True).stdout


def fetch_upstream(workdir: str, ref: str | None) -> tuple[str, str]:
    """Клонирует Maasea/sgmodule и возвращает (sha, дата) нужного коммита."""
    run(["git", "clone", "-q", "--filter=blob:none", "--no-checkout", UPSTREAM_GIT, workdir])
    if ref:
        sha = run(["git", "rev-parse", ref], cwd=workdir).strip()
    else:
        sha = run(["git", "log", "-1", "--format=%H", "origin/HEAD", "--",
                   UPSTREAM_MODULE, UPSTREAM_SCRIPT_DIR], cwd=workdir).strip()
    if not sha:
        raise RuntimeError("не найден коммит с изменениями YouTube в Maasea/sgmodule")
    date = run(["git", "show", "-s", "--format=%cs", sha], cwd=workdir).strip()
    return sha, date


def git_show(workdir: str, sha: str, path: str) -> bytes:
    return subprocess.run(["git", "show", f"{sha}:{path}"], cwd=workdir, check=True,
                          capture_output=True).stdout


def parse_arguments(module: str) -> list[tuple[str, str]]:
    m = re.search(r"^#!arguments=(.*)$", module, re.M)
    if not m:
        return []
    out = []
    for part in m.group(1).split(","):
        if ":" not in part:
            continue
        key, value = part.split(":", 1)
        out.append((key.strip(), value.strip()))
    return out


def parse_sections(module: str) -> tuple[dict[str, list[str]], list[str]]:
    sections: dict[str, list[str]] = {}
    order: list[str] = []
    current = None
    for line in module.split("\n"):
        s = line.strip()
        if re.fullmatch(r"\[[^\]]+\]", s):
            current = s
            if current not in sections:
                sections[current] = []
                order.append(current)
            continue
        if current is None or not s or s.startswith("#"):
            continue
        sections[current].append(s)
    return sections, order


def script_param(line: str, key: str) -> str | None:
    m = re.search(rf"(?:^|[=,])\s*{key}=([^,]+)", line)
    return m.group(1).strip() if m else None


def make_local(sections: dict[str, list[str]], order: list[str]) -> tuple[dict[str, list[str]], list[str]]:
    """Основной вариант: без перехватов, которые нужны только для сервера Maasea."""
    scripts_out: list[str] = []
    map_local: list[str] = []
    for line in sections.get("[Script]", []):
        stype = script_param(line, "type")
        pattern = script_param(line, "pattern") or ""
        if stype == "http-request":
            if "initplayback" in pattern:
                map_local.append(f"{pattern} {MAP_LOCAL_EMPTY}")
            elif "log_event" in pattern:
                pass  # нужен только для сбора ключей сервера Maasea
            else:
                raise RuntimeError(f"неизвестный http-request в модуле Maasea, нужна ручная проверка: {line[:120]}")
            continue
        if stype == "http-response":
            line = line.replace("|log_event", "").replace("|config", "")
        scripts_out.append(line)
    if len(map_local) != 1:
        raise RuntimeError(f"ожидался ровно один перехват initplayback, найдено {len(map_local)}: формат Maasea изменился")
    out = dict(sections)
    out["[Script]"] = scripts_out
    out["[Map Local]"] = out.get("[Map Local]", []) + map_local
    new_order = list(order)
    if "[Map Local]" not in new_order:
        new_order.insert(new_order.index("[Script]"), "[Map Local]")
    return out, new_order


def build(workdir: str, sha: str, date: str) -> tuple[dict[str, str], dict[str, bytes], list[str]]:
    """Возвращает ({путь модуля: текст}, {имя скрипта: содержимое}, предупреждения)."""
    warnings: list[str] = []
    upstream = git_show(workdir, sha, UPSTREAM_MODULE).decode("utf-8").replace("\r\n", "\n")

    args = []
    rename: dict[str, str] = {}
    for key, value in parse_arguments(upstream):
        new = ARG_NAMES.get(key)
        if new is None:
            warnings.append(f"неизвестный параметр Maasea «{key}», оставлен без перевода")
            new = key
        rename[key] = new
        args.append((new, ARG_DEFAULTS.get(new, value)))
    arguments = ",".join(f"{k}:{v}" for k, v in args)
    arguments_desc = "\\n\\n".join(ARG_DESC.get(k, k) for k, _ in args)

    sections, order = parse_sections(upstream)
    if not sections.get("[Script]"):
        raise RuntimeError("в модуле Maasea нет секции [Script] — формат изменился, нужна ручная проверка")
    if "[MITM]" not in sections:
        raise RuntimeError("в модуле Maasea нет секции [MITM] — формат изменился, нужна ручная проверка")

    scripts: dict[str, bytes] = {}

    def rewrite(line: str) -> str:
        for key, new in rename.items():
            line = line.replace("{{{" + key + "}}}", "{{{" + new + "}}}")
        line = MAX_SIZE_RE.sub(MAX_SIZE, line)

        def repl(m: re.Match) -> str:
            name = m.group(1)
            if name not in scripts:
                scripts[name] = git_show(workdir, sha, f"{UPSTREAM_SCRIPT_DIR}/{name}")
            return f"{OUR_RAW}{name}?v={sha[:7]}"
        return UPSTREAM_RAW_RE.sub(repl, line)

    modules: dict[str, str] = {}
    declared = {k for k, _ in args}
    for path, variant in VARIANTS.items():
        secs, ordr = (sections, order) if variant["worker"] else make_local(sections, order)
        body: list[str] = []
        rules = EXTRA_RULES + [rewrite(l) for l in secs.get("[Rule]", [])]
        body += ["[Rule]", *rules, ""]
        for name in ordr:
            if name == "[Rule]" or not secs.get(name):
                continue
            body += [name, *[rewrite(l) for l in secs[name]], ""]
        text = HEADER.format(name=variant["name"], desc=variant["desc"], arguments=arguments,
                             arguments_desc=arguments_desc, git=UPSTREAM_GIT, sha=sha, date=date)
        text += "\n" + "\n".join(body).rstrip("\n") + "\n"

        # Самопроверки.
        for ph in set(re.findall(r"\{\{\{([^}]+)\}\}\}", text)):
            if ph not in declared:
                raise RuntimeError(f"{path}: используется {{{{{{{ph}}}}}}}, но его нет в #!arguments")
        if "raw.githubusercontent.com/Maasea" in text:
            raise RuntimeError(f"{path}: остались ссылки на Maasea, которые генератор не распознал")
        if not variant["worker"] and ("youtube.request" in text or "workers.dev" in text):
            raise RuntimeError(f"{path}: в основном варианте остался перехват для сервера Maasea")
        modules[path] = text

    for name, data in scripts.items():
        if len(data) < 1000:
            raise RuntimeError(f"скрипт {name} подозрительно маленький ({len(data)} байт)")
    return modules, scripts, warnings


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ref", help="коммит или ветка Maasea/sgmodule (по умолчанию последний с изменениями YouTube)")
    ap.add_argument("--check", action="store_true", help="ничего не записывать, exit 1 если модули устарели")
    args = ap.parse_args()

    with tempfile.TemporaryDirectory() as tmp:
        workdir = os.path.join(tmp, "sgmodule")
        sha, date = fetch_upstream(workdir, args.ref)
        modules, scripts, warnings = build(workdir, sha, date)

    for w in warnings:
        print(f"предупреждение: {w}")

    changes: list[str] = []
    for path, text in modules.items():
        old = open(path, encoding="utf-8").read() if os.path.isfile(path) else ""
        if old != text:
            changes.append(path)
    for name, data in scripts.items():
        path = os.path.join(OUT_SCRIPT_DIR, name)
        if not os.path.isfile(path) or open(path, "rb").read() != data:
            changes.append(path)

    print(f"Maasea/sgmodule {sha[:7]} от {date}; скрипты: {', '.join(sorted(scripts))}")
    if not changes:
        print("Модули и скрипты актуальны.")
        return 0
    if args.check:
        print("Требуют обновления: " + ", ".join(changes))
        return 1
    for path, text in modules.items():
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
    for name, data in scripts.items():
        with open(os.path.join(OUT_SCRIPT_DIR, name), "wb") as fh:
            fh.write(data)
    print("Обновлено: " + ", ".join(changes))
    return 0


if __name__ == "__main__":
    sys.exit(main())
