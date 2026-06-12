#!/usr/bin/env python3
"""Print and validate the Wuyun skill catalog."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parents[1]
CATALOG_PATHS = [REPO_ROOT / "wuyun" / "references" / "catalog.json", REPO_ROOT / "catalog.json"]


def load_catalog() -> dict:
    for path in CATALOG_PATHS:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    raise FileNotFoundError("catalog.json not found")


def check_catalog(catalog: dict, root: Path) -> list[str]:
    errors = []
    names = [entry.get("name") for entry in catalog.get("skills", [])]
    if len(names) != len(set(names)):
        errors.append("duplicate skill names in catalog")
    for name in names:
        if not name:
            errors.append("empty skill name")
            continue
        skill_dir = root / name
        if not (skill_dir / "SKILL.md").exists():
            errors.append(f"catalog skill missing SKILL.md: {name}")
    return errors


def print_markdown(catalog: dict) -> None:
    print("# Wuyun Skill Catalog")
    print()
    print(f"- Version: `{catalog.get('version', 'unknown')}`")
    print(f"- Skills: `{len(catalog.get('skills', []))}`")
    print(f"- Frameworks: {', '.join(catalog.get('frameworks', []))}")
    print()
    print("| Skill | Domains | Risk | Tools |")
    print("|---|---|---|---|")
    for entry in catalog.get("skills", []):
        print(f"| `{entry.get('name')}` | {', '.join(entry.get('domains', []))} | `{entry.get('risk', '')}` | {', '.join(entry.get('tools', []))} |")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Show or check the Wuyun skill catalog.")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    parser.add_argument("--skill", help="show one skill by name")
    parser.add_argument("--check", action="store_true", help="validate catalog skill directories")
    args = parser.parse_args(argv)
    catalog = load_catalog()
    if args.skill:
        skills = [s for s in catalog.get("skills", []) if s.get("name") == args.skill]
        catalog = {**catalog, "skills": skills}
    if args.check:
        errors = check_catalog(catalog if not args.skill else load_catalog(), REPO_ROOT)
        if errors:
            for err in errors:
                print(f"FAIL: {err}", file=sys.stderr)
            return 1
        if not args.json:
            print("PASS: catalog matches skill directories")
    if args.json:
        print(json.dumps(catalog, ensure_ascii=False, indent=2))
    elif not args.check or args.skill:
        print_markdown(catalog)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
