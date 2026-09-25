#!/usr/bin/env python3
"""
Сборка modules/YT-Premium-V1-RU.module из актуального модуля YouTube Enhance (Maasea/sgmodule).

Запуск:
    python github_actions/sync_youtube_module.py            # обновить модуль и скрипты
    python github_actions/sync_youtube_module.py --check    # только проверить, exit 1 если есть что обновить
    python github_actions/sync_youtube_module.py --ref <sha> # собрать из конкретного коммита Maasea

Зачем: скрипты Maasea и строки [Script] в модуле меняются вместе (например, в июле 2026 добавились
перехват googlevideo.com/initplayback и youtubei/v1/log_event). Если обновить только скрипт, модуль
перестаёт резать часть рекламы. Поэтому генератор:
  1. находит последний коммит Maasea/sgmodule, который менял YouTube.Enhance.sgmodule или Script/Youtube;
  2. берёт из него модуль и все скрипты, на которые модуль ссылается;
  3. кладёт скрипты в Script/ этого репозитория, а в модуле ссылается на них с ?v=<коммит>,
     чтобы Shadowrocket скачал новую версию сразу после обновления модуля;
  4. переименовывает параметры (#!arguments) с китайских на английские и подставляет наши значения
     по умолчанию;
  5. подгоняет параметры скриптов под Shadowrocket: max-size=0, как в «родном» для Shadowrocket
     модуле iab0x00/ProxyRules (его рекомендует автор руководства Shadowrocket LOWERTOP).

Отдельных правил блокировки QUIC в модуле нет, как и у Maasea и iab0x00: Shadowrocket по умолчанию
блокирует QUIC для соединений через прокси (block-quic = all-proxy), а YouTube в SR_RU.conf идёт через
прокси, поэтому приложение и так переходит на TCP, где работает расшифровка.

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

OUT_MODULE = "modules/YT-Premium-V1-RU.module"
OUT_SCRIPT_DIR = "Script"
OUR_RAW = "https://raw.githubusercontent.com/newzealandgrom/Shadowrocket-routing/refs/heads/master/Script/"

# Имена параметров Maasea -> наши. Неизвестный параметр остаётся с исходным именем (с предупреждением).
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

HEADER = """#!name=YouTube Premium RU
#!desc=Убирает рекламу в YouTube и YouTube Music, включает картинку в картинке и фоновое воспроизведение. Нужен установленный и доверенный MITM-сертификат. Основан на YouTube Enhance (Maasea).
#!arguments={arguments}
#!arguments-desc={arguments_desc}
#!homepage=https://github.com/newzealandgrom/Shadowrocket-routing
# Источник: {git}, коммит {sha} ({date}), лицензия Apache-2.0.
# Файл генерирует github_actions/sync_youtube_module.py: правки вносите в генератор, а не сюда.
"""

# Наши дополнения к [Rule] (сейчас не нужны, см. описание выше).
EXTRA_RULES: list[str] = []

# Замены в строках [Script] под Shadowrocket.
SCRIPT_TWEAKS = [
    ("max-size=-1", "max-size=0"),
]


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


def build(workdir: str, sha: str, date: str) -> tuple[str, dict[str, bytes], list[str]]:
    """Возвращает (текст модуля, {путь скрипта: содержимое}, предупреждения)."""
    warnings: list[str] = []
    upstream = git_show(workdir, sha, UPSTREAM_MODULE).decode("utf-8").replace("\r\n", "\n")

    # Параметры: переименование и наши значения по умолчанию.
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

    # Секции модуля Maasea (заголовки #! и комментарии отбрасываем).
    sections: dict[str, list[str]] = {}
    order: list[str] = []
    current = None
    for line in upstream.split("\n"):
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

    scripts: dict[str, bytes] = {}

    def rewrite(line: str) -> str:
        for key, new in rename.items():
            line = line.replace("{{{" + key + "}}}", "{{{" + new + "}}}")
        for old, new in SCRIPT_TWEAKS:
            line = line.replace(old, new)

        def repl(m: re.Match) -> str:
            name = m.group(1)
            if name not in scripts:
                scripts[name] = git_show(workdir, sha, f"{UPSTREAM_SCRIPT_DIR}/{name}")
            return f"{OUR_RAW}{name}?v={sha[:7]}"
        return UPSTREAM_RAW_RE.sub(repl, line)

    body: list[str] = []
    rules = EXTRA_RULES + [rewrite(l) for l in sections.get("[Rule]", [])]
    if rules:
        body += ["[Rule]", *rules, ""]
    for name in order:
        if name == "[Rule]":
            continue
        body += [name, *[rewrite(l) for l in sections[name]], ""]

    text = HEADER.format(arguments=arguments, arguments_desc=arguments_desc,
                         git=UPSTREAM_GIT, sha=sha, date=date) + "\n" + "\n".join(body).rstrip("\n") + "\n"

    # Самопроверки: каждый {{{параметр}}} объявлен, скрипты не пустые, есть [Script] и [MITM].
    declared = {k for k, _ in args}
    for ph in set(re.findall(r"\{\{\{([^}]+)\}\}\}", text)):
        if ph not in declared:
            raise RuntimeError(f"в модуле используется {{{{{{{ph}}}}}}}, но его нет в #!arguments")
    if "[Script]" not in sections or not sections["[Script]"]:
        raise RuntimeError("в модуле Maasea нет секции [Script] — формат изменился, нужна ручная проверка")
    if "[MITM]" not in sections:
        raise RuntimeError("в модуле Maasea нет секции [MITM] — формат изменился, нужна ручная проверка")
    if "raw.githubusercontent.com/Maasea" in text:
        raise RuntimeError("в модуле остались ссылки на Maasea, которые генератор не распознал")
    for name, data in scripts.items():
        if len(data) < 1000:
            raise RuntimeError(f"скрипт {name} подозрительно маленький ({len(data)} байт)")
    return text, scripts, warnings


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ref", help="коммит или ветка Maasea/sgmodule (по умолчанию последний с изменениями YouTube)")
    ap.add_argument("--check", action="store_true", help="ничего не записывать, exit 1 если модуль устарел")
    args = ap.parse_args()

    with tempfile.TemporaryDirectory() as tmp:
        workdir = os.path.join(tmp, "sgmodule")
        sha, date = fetch_upstream(workdir, args.ref)
        text, scripts, warnings = build(workdir, sha, date)

    for w in warnings:
        print(f"предупреждение: {w}")

    changes: list[str] = []
    old = open(OUT_MODULE, encoding="utf-8").read() if os.path.isfile(OUT_MODULE) else ""
    if old != text:
        changes.append(OUT_MODULE)
    for name, data in scripts.items():
        path = os.path.join(OUT_SCRIPT_DIR, name)
        if not os.path.isfile(path) or open(path, "rb").read() != data:
            changes.append(path)

    print(f"Maasea/sgmodule {sha[:7]} от {date}; скрипты: {', '.join(sorted(scripts))}")
    if not changes:
        print("Модуль и скрипты актуальны.")
        return 0
    if args.check:
        print("Требуют обновления: " + ", ".join(changes))
        return 1
    with open(OUT_MODULE, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    for name, data in scripts.items():
        with open(os.path.join(OUT_SCRIPT_DIR, name), "wb") as fh:
            fh.write(data)
    print("Обновлено: " + ", ".join(changes))
    return 0


if __name__ == "__main__":
    sys.exit(main())
