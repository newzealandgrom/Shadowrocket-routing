#!/usr/bin/env python3
"""
Проверка дубликатов доменов между разными .list файлами
"""
import glob
import os
from collections import defaultdict


def extract_domain(line: str):
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    if "," in line:
        parts = line.split(",", 1)
        domain = parts[1].strip().lower() if len(parts) > 1 else line.lower()
    else:
        domain = line.lower()

    if domain and "." in domain and not domain.startswith(("http", "https", "/")):
        return domain
    return None


def main():
    domain_to_files = defaultdict(set)

    for filepath in sorted(glob.glob("lists/*.list")):
        filename = os.path.basename(filepath)
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    domain = extract_domain(line)
                    if domain:
                        domain_to_files[domain].add(filename)
        except Exception as e:
            print(f"Ошибка при чтении {filename}: {e}")

    duplicates = {d: sorted(files) for d, files in domain_to_files.items() if len(files) > 1}

    if duplicates:
        print("❌ Найдены дубликаты доменов между файлами:\n")
        for domain, files in sorted(duplicates.items()):
            print(f"  {domain}")
            for f in files:
                print(f"    → {f}")
        print(f"\nВсего дублирующихся доменов: {len(duplicates)}")
        exit(1)
    else:
        print("✅ Дубликатов между разными .list файлами не найдено.")
        exit(0)


if __name__ == "__main__":
    main()
