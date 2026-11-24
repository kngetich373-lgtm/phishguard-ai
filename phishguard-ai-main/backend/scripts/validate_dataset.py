from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path
from urllib.parse import urlsplit


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("dataset", type=Path)
    args = parser.parse_args()
    if not args.dataset.is_file():
        print(f"Dataset not found: {args.dataset}", file=sys.stderr)
        return 2

    required = {"url", "label"}
    total = 0
    seen_urls = set()
    duplicates = 0
    invalid = 0
    with args.dataset.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None or not required.issubset(set(reader.fieldnames)):
            print("Dataset requires url and label columns", file=sys.stderr)
            return 2
        for row in reader:
            total += 1
            url = row["url"].strip()
            label = row["label"].strip().lower()
            parsed = urlsplit(url if "://" in url else "http://" + url)
            if not parsed.hostname or label not in {"legitimate", "phishing"}:
                invalid += 1
                continue
            normalized = parsed.hostname.lower() + parsed.path
            if normalized in seen_urls:
                duplicates += 1
            seen_urls.add(normalized)

    print(f"total={total} duplicates={duplicates} invalid={invalid}")
    return 1 if invalid else 0


if __name__ == "__main__":
    raise SystemExit(main())
