#!/usr/bin/env python3
"""Project or cross-project Wuyun knowledge base helper."""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path


KINDS = ["signature", "validation", "framework", "payload", "false-positive"]
SENSITIVE_RE = re.compile(r"(?i)(api[_-]?key|secret|token|password|credential|cookie)\s*[:=]\s*['\"]?[A-Za-z0-9_./+=-]{16,}")
DEFAULT_SEEDS = {
    "signature": [
        {"name": "webcrypto-hmac-signature", "summary": "Client code calls crypto.subtle.importKey/sign near timestamp, nonce, or canonical request fields.", "tags": ["js", "webcrypto", "signature"], "confidence": "medium"},
        {"name": "wasm-assisted-signature", "summary": "JS glue delegates request signing or checksum construction into WASM exports.", "tags": ["js", "wasm", "signature"], "confidence": "medium"},
    ],
    "validation": [
        {"name": "idor-two-owned-accounts", "summary": "Use two owned accounts and synthetic objects; compare access to each object's metadata-only response.", "tags": ["idor", "bola", "authz"], "confidence": "high"},
        {"name": "graphql-field-authz", "summary": "Check field-level authorization with safe typename/introspection and synthetic object references.", "tags": ["graphql", "authz"], "confidence": "medium"},
    ],
    "framework": [
        {"name": "nextjs-public-env", "summary": "NEXT_PUBLIC variables are intentionally client-visible; classify as exposure only when value grants unintended access.", "tags": ["nextjs", "frontend", "false-positive"], "confidence": "high"},
        {"name": "spring-actuator-surface", "summary": "Actuator endpoints require environment-specific auth and exposure review; do not assume impact from route presence alone.", "tags": ["spring", "actuator"], "confidence": "medium"},
    ],
    "payload": [
        {"name": "benign-canary-marker", "summary": "Use a harmless marker string to prove influence without extracting secrets or changing data.", "tags": ["validation", "safe"], "confidence": "high"},
    ],
    "false-positive": [
        {"name": "jwt-shape-in-docs", "summary": "JWT-looking strings in examples/docs are not credentials unless tied to live environment or privileged scope.", "tags": ["jwt", "docs"], "confidence": "high"},
    ],
}


def kb_dir(args: argparse.Namespace) -> Path:
    if args.global_kb:
        return Path.home() / ".wuyun" / "knowledge"
    return Path(args.kb_dir).resolve()


def sanitize(value: str) -> str:
    return SENSITIVE_RE.sub(lambda m: m.group(1) + "=<redacted>", value)


def entry_path(root: Path, kind: str) -> Path:
    return root / f"{kind}.jsonl"


def read_entries(root: Path, kind: str | None = None) -> list[dict]:
    kinds = [kind] if kind else KINDS
    entries = []
    for item in kinds:
        path = entry_path(root, item)
        if not path.exists():
            continue
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.strip():
                entries.append(json.loads(line))
    return entries


def append_entry(root: Path, entry: dict) -> None:
    root.mkdir(parents=True, exist_ok=True)
    path = entry_path(root, entry["kind"])
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n")


def seed(root: Path) -> int:
    for kind, rows in DEFAULT_SEEDS.items():
        existing = {entry.get("name") for entry in read_entries(root, kind)}
        for row in rows:
            if row["name"] in existing:
                continue
            append_entry(root, {
                "kind": kind,
                "name": row["name"],
                "summary": row["summary"],
                "tags": row["tags"],
                "confidence": row["confidence"],
                "evidence": "",
                "created_at": int(time.time()),
            })
    print(f"seeded knowledge base: {root}")
    return 0


def add(args: argparse.Namespace) -> int:
    root = kb_dir(args)
    entry = {
        "kind": args.kind,
        "name": sanitize(args.name),
        "summary": sanitize(args.summary),
        "tags": [item.strip() for chunk in args.tag for item in chunk.split(",") if item.strip()],
        "confidence": args.confidence,
        "evidence": sanitize(args.evidence or ""),
        "created_at": int(time.time()),
    }
    append_entry(root, entry)
    print(json.dumps(entry, ensure_ascii=False, indent=2))
    return 0


def search(args: argparse.Namespace) -> int:
    root = kb_dir(args)
    query = args.query.lower()
    rows = []
    for entry in read_entries(root, args.kind):
        haystack = " ".join([entry.get("name", ""), entry.get("summary", ""), " ".join(entry.get("tags", []))]).lower()
        if query in haystack:
            rows.append(entry)
    print(json.dumps({"kb_dir": str(root), "count": len(rows), "entries": rows}, ensure_ascii=False, indent=2))
    return 0


def list_entries(args: argparse.Namespace) -> int:
    root = kb_dir(args)
    rows = read_entries(root, args.kind)
    print(json.dumps({"kb_dir": str(root), "count": len(rows), "entries": rows}, ensure_ascii=False, indent=2))
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Manage Wuyun reusable research knowledge.")
    parser.add_argument("--kb-dir", default=".wuyun/knowledge", help="project-local knowledge directory")
    parser.add_argument("--global-kb", action="store_true", help="use ~/.wuyun/knowledge for cross-project patterns")
    sub = parser.add_subparsers(dest="command", required=True)

    seed_cmd = sub.add_parser("seed")
    seed_cmd.set_defaults(func=lambda args: seed(kb_dir(args)))

    add_cmd = sub.add_parser("add")
    add_cmd.add_argument("--kind", required=True, choices=KINDS)
    add_cmd.add_argument("--name", required=True)
    add_cmd.add_argument("--summary", required=True)
    add_cmd.add_argument("--tag", action="append", default=[])
    add_cmd.add_argument("--confidence", choices=["high", "medium", "low"], default="medium")
    add_cmd.add_argument("--evidence", default="")
    add_cmd.set_defaults(func=add)

    search_cmd = sub.add_parser("search")
    search_cmd.add_argument("query")
    search_cmd.add_argument("--kind", choices=KINDS)
    search_cmd.set_defaults(func=search)

    list_cmd = sub.add_parser("list")
    list_cmd.add_argument("--kind", choices=KINDS)
    list_cmd.set_defaults(func=list_entries)

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
