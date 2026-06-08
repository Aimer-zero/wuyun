#!/usr/bin/env python3
"""Generate route/API wordlists from local Wuyun artifacts or text files."""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path


ROUTE_RE = re.compile(r"(?<![A-Za-z0-9])/(?:api/|v\d+/|admin/|internal/|auth/|oauth/|graphql|upload|files|webhook|socket)[A-Za-z0-9._~:/{}?#\[\]@!$&'()*+,;=%-]*")


def collect_from_json(value) -> set[str]:
    out: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            if key in {"evidence", "url", "path"} and isinstance(child, str):
                out.update(ROUTE_RE.findall(child))
            out.update(collect_from_json(child))
    elif isinstance(value, list):
        for item in value:
            out.update(collect_from_json(item))
    elif isinstance(value, str):
        out.update(ROUTE_RE.findall(value))
    return out


def normalize(route: str) -> str:
    route = route.split("?")[0]
    route = re.sub(r"\{[^/]+\}", "FUZZ", route)
    route = re.sub(r":\w+", "FUZZ", route)
    return route.strip("/")


def iter_inputs(path: Path, max_files: int, max_size: int):
    if path.is_file():
        yield path
        return
    count = 0
    for dirpath, dirnames, filenames in os.walk(path):
        dirnames[:] = [d for d in dirnames if d not in {".git", "node_modules", ".wuyun", "dist", "build"}]
        for filename in filenames:
            item = Path(dirpath) / filename
            if item.suffix.lower() not in {".js", ".ts", ".tsx", ".jsx", ".json", ".har", ".map", ".txt", ".md", ".yaml", ".yml"}:
                continue
            try:
                if item.stat().st_size > max_size:
                    continue
            except OSError:
                continue
            count += 1
            if count > max_files:
                return
            yield item


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Build route wordlist from local artifacts.")
    parser.add_argument("path")
    parser.add_argument("--output")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--max-files", type=int, default=5000)
    parser.add_argument("--max-size", type=int, default=2_000_000)
    args = parser.parse_args(argv)
    path = Path(args.path).resolve()
    if not path.exists():
        print(f"error: path does not exist: {path}", file=sys.stderr)
        return 2
    routes = set()
    files = list(iter_inputs(path, args.max_files, args.max_size))
    for item in files:
        text = item.read_text(encoding="utf-8", errors="replace")
        routes.update(ROUTE_RE.findall(text))
        try:
            routes.update(collect_from_json(json.loads(text)))
        except json.JSONDecodeError:
            pass
    words = sorted({normalize(route) for route in routes if normalize(route)})
    payload = {"source": str(path), "files_scanned": len(files), "count": len(words), "wordlist": words}
    if args.output:
        Path(args.output).write_text("\n".join(words) + ("\n" if words else ""), encoding="utf-8")
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print("# Wuyun Route Wordlist")
        print()
        print(f"- Source: `{path}`")
        print(f"- Count: `{len(words)}`")
        for word in words:
            print(word)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
