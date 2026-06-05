#!/usr/bin/env python3
"""Create a project-local Wuyun memory skeleton.

This is a fallback for environments without managed agent memory. It creates
redaction-first files and never overwrites existing notes unless --force is used.
"""
from __future__ import annotations

import argparse
import datetime as dt
import sys
from pathlib import Path

MEMORY_TEMPLATE = """# Wuyun Project Memory

Created: {date}

Purpose: store reusable, redacted vulnerability research knowledge for this project.
Do not store secrets, tokens, credentials, customer data, raw exploit artifacts, or unrelated personal data.

## Entries

<!-- Add entries using references/memory-schema.md. Keep evidence pointers non-sensitive. -->
"""

EVIDENCE_INDEX_TEMPLATE = """# Wuyun Evidence Index

Created: {date}

Use this file for pointers to non-sensitive evidence only: file paths, commit IDs,
request IDs, report sections, sanitized screenshots, or reproduction notes.
Do not paste secrets, credentials, database contents, or private data.
"""


def write_file(path: Path, content: str, force: bool) -> str:
    if path.exists() and not force:
        return f"kept existing {path}"
    path.write_text(content, encoding="utf-8")
    return f"wrote {path}"


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Initialize project-local Wuyun memory files.")
    parser.add_argument("path", nargs="?", default=".", help="project root")
    parser.add_argument("--force", action="store_true", help="overwrite existing memory.md/evidence-index.md")
    args = parser.parse_args(argv)

    root = Path(args.path).resolve()
    if not root.exists() or not root.is_dir():
        print(f"error: not a directory: {root}", file=sys.stderr)
        return 2

    wuyun = root / ".wuyun"
    findings = wuyun / "findings"
    wuyun.mkdir(exist_ok=True)
    findings.mkdir(exist_ok=True)

    today = dt.date.today().isoformat()
    messages = [
        write_file(wuyun / "memory.md", MEMORY_TEMPLATE.format(date=today), args.force),
        write_file(wuyun / "evidence-index.md", EVIDENCE_INDEX_TEMPLATE.format(date=today), args.force),
        f"ensured {findings}",
    ]
    print("# Wuyun Memory Initialization")
    for message in messages:
        print(f"- {message}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
