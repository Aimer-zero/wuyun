#!/usr/bin/env python3
"""Passive JavaScript obfuscation and signature triage.

Reads local files only. It does not execute JavaScript or transform artifacts.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


SKIP_DIRS = {".git", "node_modules", ".wuyun", ".codex", ".claude", "coverage", ".next/cache"}
EXTS = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".map", ".html", ".wasm"}


@dataclass
class Hit:
    category: str
    rule: str
    file: str
    line: int
    evidence: str
    confidence_hint: str


RULES: list[tuple[str, str, str, str]] = [
    ("packing", "eval-or-function", r"\b(?:eval|Function)\s*\(", "high-signal"),
    ("packing", "string-exec", r"\b(?:setTimeout|setInterval)\s*\(\s*['\"]", "medium-signal"),
    ("string-array", "array-indexer", r"\b(?:var|let|const)\s+[_$A-Za-z][\w$]*\s*=\s*\[(?:\s*['\"][^'\"]{2,}['\"]\s*,?){6,}", "medium-signal"),
    ("encoding", "hex-unicode-heavy", r"(?:\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}){4,}", "medium-signal"),
    ("control-flow", "while-switch-dispatch", r"while\s*\(\s*!!\[\]\s*\|?\|?\s*true\s*\)|while\s*\(\s*true\s*\).*switch\s*\(", "medium-signal"),
    ("anti-debug", "debugger-loop", r"\bdebugger\b|constructor\s*\(\s*['\"]debugger['\"]", "context-signal"),
    ("bundler", "webpack-runtime", r"__webpack_require__|webpackChunk|webpackJsonp", "bundler"),
    ("bundler", "vite-runtime", r"import\.meta\.env|/@vite/client|__vite", "bundler"),
    ("crypto", "cryptojs", r"\bCryptoJS\b|HmacSHA|SHA256|MD5|AES\.encrypt|AES\.decrypt", "crypto-signal"),
    ("crypto", "webcrypto", r"\bcrypto\.subtle\b|SubtleCrypto|importKey|sign\s*\(|digest\s*\(", "crypto-signal"),
    ("signature", "signature-params", r"(?i)\b(?:signature|sign|nonce|timestamp|canonical|x-sign|x-timestamp|x-nonce|device[_-]?id|risk[_-]?token)\b", "signature-signal"),
    ("wasm", "webassembly", r"\bWebAssembly\.(?:instantiate|instantiateStreaming|compile)|\.wasm\b|wasm_bindgen|__wbg_|HEAPU8|ccall|cwrap", "wasm-signal"),
    ("sourcemap", "source-map-ref", r"sourceMappingURL=([^\s*]+)", "sourcemap"),
]
COMPILED = [(cat, rule, re.compile(pattern), confidence) for cat, rule, pattern, confidence in RULES]


def iter_files(root: Path, max_files: int, max_size: int) -> Iterable[Path]:
    if root.is_file():
        if root.suffix.lower() in EXTS:
            yield root
        return
    count = 0
    for dirpath, dirnames, filenames in os.walk(root):
        base = Path(dirpath)
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for filename in filenames:
            path = base / filename
            if path.suffix.lower() not in EXTS:
                continue
            try:
                if path.stat().st_size > max_size:
                    continue
            except OSError:
                continue
            count += 1
            if count > max_files:
                return
            yield path


def compact(text: str, complete: bool) -> str:
    value = " ".join(text.strip().split())
    if not complete and len(value) > 220:
        value = value[:217] + "..."
    return value


def scan_file(path: Path, root: Path, complete: bool) -> list[Hit]:
    hits: list[Hit] = []
    if path.suffix.lower() == ".wasm":
        rel = str(path.relative_to(root)) if root.is_dir() else path.name
        hits.append(Hit("wasm", "wasm-file", rel, 1, "WASM binary artifact", "artifact"))
        return hits
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return hits
    rel = str(path.relative_to(root)) if root.is_dir() else path.name
    for lineno, line in enumerate(text.splitlines(), start=1):
        for category, rule, regex, confidence in COMPILED:
            if regex.search(line):
                hits.append(Hit(category, rule, rel, lineno, compact(line, complete), confidence))
    return hits


def transform_plan(categories: set[str], rules: set[str]) -> list[str]:
    steps: list[str] = []
    if "sourcemap" in categories:
        steps.append("Recover and verify sourcemaps before manual deobfuscation.")
    if "bundler" in categories:
        steps.append("Recover bundler module map and isolate request/signing modules.")
    if "string-array" in categories or "encoding" in categories:
        steps.append("Decode literal encodings and string arrays with an AST transform, then diff decoded constants.")
    if "control-flow" in categories:
        steps.append("Identify dispatcher variable and reconstruct basic blocks before renaming symbols.")
    if "packing" in categories:
        steps.append("Unpack eval/Function payload only in a local lab or by static extraction; do not execute unknown code.")
    if "crypto" in categories or "signature" in categories:
        steps.append("Trace signing inputs: method, path, query, body hash, timestamp, nonce, token, and device/risk identifiers.")
    if "wasm" in categories:
        steps.append("Extract WASM imports/exports/strings and link JS glue callers to request construction.")
    if "debugger-loop" in rules:
        steps.append("Treat anti-debug/self-defending code as an observation blocker; avoid stealth bypass and request owner/lab support if needed.")
    return steps or ["No specific deobfuscation pipeline selected from configured signals; continue normal JS reverse extraction."]


def analyze(path: Path, max_files: int, max_size: int, complete: bool) -> dict:
    root = path.resolve()
    files = list(iter_files(root, max_files=max_files, max_size=max_size))
    hits: list[Hit] = []
    for item in files:
        hits.extend(scan_file(item, root if root.is_dir() else item.parent, complete))
    categories = {hit.category for hit in hits}
    rules = {hit.rule for hit in hits}
    return {
        "artifact": str(root),
        "files_scanned": len(files),
        "summary": dict(Counter(hit.category for hit in hits).most_common()),
        "hits": [asdict(hit) for hit in hits],
        "transform_plan": transform_plan(categories, rules),
        "limits": [
            "triage only; no JavaScript execution or automatic transformation performed",
            "obfuscation signals are leads and require semantic validation",
            "signature recovery does not prove server-side weakness without replay or source evidence",
        ],
    }


def print_markdown(payload: dict) -> None:
    print("# Wuyun JS Deobfuscation Triage")
    print()
    print(f"- Artifact: `{payload['artifact']}`")
    print(f"- Files scanned: `{payload['files_scanned']}`")
    print()
    print("## Summary")
    if payload["summary"]:
        for category, count in payload["summary"].items():
            print(f"- `{category}`: {count}")
    else:
        print("- No configured obfuscation/signature signals found.")
    print()
    print("## Hits")
    for hit in payload["hits"][:160]:
        print(f"- `{hit['category']}` / `{hit['rule']}` at `{hit['file']}:{hit['line']}`: {hit['evidence']}")
    if len(payload["hits"]) > 160:
        print(f"- ... {len(payload['hits']) - 160} additional hits omitted; use `--json` for full output.")
    print()
    print("## Transform Plan")
    for step in payload["transform_plan"]:
        print(f"- {step}")
    print()
    print("## Limits")
    for item in payload["limits"]:
        print(f"- {item}")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Passively triage obfuscated JavaScript and signing logic.")
    parser.add_argument("path", help="JS/WASM file or directory")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    parser.add_argument("--complete-evidence", action="store_true", help="do not compact long evidence lines")
    parser.add_argument("--max-files", type=int, default=5000)
    parser.add_argument("--max-size", type=int, default=2_000_000)
    args = parser.parse_args(argv)

    path = Path(args.path).resolve()
    if not path.exists():
        print(f"error: path does not exist: {path}", file=sys.stderr)
        return 2
    payload = analyze(path, args.max_files, args.max_size, args.complete_evidence)
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print_markdown(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
