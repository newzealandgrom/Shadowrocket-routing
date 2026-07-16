#!/usr/bin/env python3
"""
Проверка дубликатов доменов между разными .list файлами в папке lists/
"""
import glob
import os
from collections import defaultdict

def extract_domain(line: str) -> str | None:
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    # Обрабатываем форматы: DOMAIN-SUFFIX,example.com  или  просто example.com
    if "," in line:
        parts = line.split(",", 1)
        if len(parts) > 1:
            domain = parts[1].strip().lower()
        else:
            domain = line.lower()
    else:
        domain = line.lower()

    # Простая фильтрация — только строки, похожие на домены
    if domain and "." in domain and not domain.startswith(("http", "https", "/")):
        return domain
    return None


def main():
    domain_to_files = defaultdict(set)

    list_files = sorted(glob.glob("lists/*.list"))
    if not list_files:
        print("Папка lists/ пуста или не найдена.")
        return

    for filepath in list_files:
        filename = os.path.basename(filepath)
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                domain = extract_domain(line)
                if domain:
                    domain_to_files[domain].add(filename)

    # Ищем домены, которые встречаются больше чем в одном файле
    duplicates = {
        domain: sorted(files)
        for domain, files in domain_to_files.items()
        if len(files) > 1
    }

    if duplicates:
        print("❌ Найдены дубликаты доменов между разными файлами:\n")
        for domain, files in sorted(duplicates.items()):
            print(f"  {domain}")
            for f in files:
                print(f"    → {f}")
        print(f"\nВсего дублирующихся доменов: {len(duplicates)}")
        exit(1)
    else:
        print("✅ Дубликатов доменов между разными .list файлами не найдено.")
        exit(0)


if __name__ == "__main__":
    main()
