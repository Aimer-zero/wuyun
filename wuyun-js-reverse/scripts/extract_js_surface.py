#!/usr/bin/env python3
"""Passive JavaScript/API surface extractor for Wuyun JS reverse workflows.

This script reads local files only. It does not execute JavaScript, contact
targets, fetch sourcemaps, or validate endpoints.
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


SKIP_DIRS = {
    ".git", ".hg", ".svn", ".idea", ".vscode", ".codex", ".claude", ".wuyun",
    "node_modules", "dist", "build", "coverage", ".next/cache", ".nuxt", "__pycache__",
}
JS_EXTS = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".vue", ".svelte", ".map", ".json", ".html", ".htm"}


@dataclass
class Hit:
    category: str
    rule: str
    file: str
    line: int
    evidence: str
    confidence_hint: str


RULES: list[tuple[str, str, str, str]] = [
    ("endpoint", "absolute-url", r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+", "literal"),
    ("endpoint", "api-path", r"['\"]((?:/|\\u002f)(?:api|graphql|v\d+|admin|internal|auth|oauth|upload|files|webhook|socket|ws)[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]*)['\"]", "literal"),
    ("endpoint", "graphql-operation", r"\b(?:query|mutation|subscription)\s+[A-Za-z_][A-Za-z0-9_]*\s*(?:\(|\{)", "graphql"),
    ("endpoint", "websocket", r"\b(?:new\s+WebSocket|socket\.io|io\s*\(|wss?://)", "runtime-call"),
    ("request", "fetch-wrapper", r"\b(?:fetch|axios|XMLHttpRequest|superagent|request|ky|graphqlRequest|ApolloClient|urql)\b", "callsite"),
    ("auth", "auth-header", r"(?i)\b(?:Authorization|Bearer|X-CSRF|X-XSRF|csrfToken|accessToken|refreshToken|idToken)\b", "auth-signal"),
    ("auth", "browser-storage", r"\b(?:localStorage|sessionStorage|document\.cookie|indexedDB|cookieStore)\b", "storage-signal"),
    ("crypto", "signing-or-crypto", r"(?i)\b(?:hmac|sha256|sha1|md5|crypto\.subtle|createHash|createHmac|sign(?:ature)?|nonce|timestamp|canonical|encrypt|decrypt)\b", "crypto-signal"),
    ("sourcemap", "source-map-ref", r"sourceMappingURL=([^\s*]+)", "sourcemap"),
    ("secret", "secret-like", r"(?i)\b(?:api[_-]?key|secret|client[_-]?secret|access[_-]?key|private[_-]?key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_./+=:-]{12,})", "sensitive-pattern"),
    ("debug", "debug-or-env", r"(?i)\b(?:debug|devtools|staging|localhost|127\.0\.0\.1|internal|mock|sandbox|testnet)\b", "context-signal"),
]
COMPILED = [(cat, rule, re.compile(pattern), confidence) for cat, rule, pattern, confidence in RULES]


def should_skip_dir(path: Path) -> bool:
    parts = path.parts
    joined = path.as_posix()
    return any(part in SKIP_DIRS for part in parts) or any(skip in joined for skip in SKIP_DIRS if "/" in skip)


def iter_files(root: Path, max_files: int, max_size: int) -> Iterable[Path]:
    if root.is_file():
        yield root
        return
    count = 0
    for dirpath, dirnames, filenames in os.walk(root):
        base = Path(dirpath)
        dirnames[:] = [d for d in dirnames if not should_skip_dir(base / d)]
        for filename in filenames:
            path = base / filename
            if path.suffix.lower() not in JS_EXTS:
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


def compact(value: str, category: str, complete: bool) -> str:
    text = " ".join(value.strip().split())
    if not complete:
        text = re.sub(
            r"(?i)(api[_-]?key|secret|client[_-]?secret|access[_-]?key|private[_-]?key|token)(\b\s*[:=]\s*)['\"]?[A-Za-z0-9_./+=:-]{12,}",
            r"\1\2<compact-sensitive-value>",
            text,
        )
        if category == "secret":
            text = "<compact-sensitive-value>"
        if len(text) > 220:
            text = text[:217] + "..."
    return text


def scan_file(path: Path, root: Path, complete: bool) -> list[Hit]:
    hits: list[Hit] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return hits
    rel = str(path.relative_to(root)) if root.is_dir() else path.name
    for lineno, line in enumerate(text.splitlines(), start=1):
        for category, rule, regex, confidence in COMPILED:
            for match in regex.finditer(line):
                evidence = match.group(1) if match.groups() else match.group(0)
                hits.append(Hit(category, rule, rel, lineno, compact(evidence, category, complete), confidence))
    return hits


def infer_framework(files: list[Path], root: Path) -> list[dict]:
    patterns = [
        ("react", r"\breact\b|React\.createElement|jsx-runtime"),
        ("vue", r"\bvue\b|createApp\s*\(|new Vue\s*\("),
        ("angular", r"@angular/|platformBrowserDynamic"),
        ("nextjs", r"\bnext\b|__NEXT_DATA__|/_next/"),
        ("vite", r"\bvite\b|import\.meta\.env"),
        ("webpack", r"webpackJsonp|__webpack_require__|webpackChunk"),
        ("apollo-graphql", r"ApolloClient|gql`|graphql-tag"),
    ]
    found: dict[str, str] = {}
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")[:250_000]
        except OSError:
            continue
        for name, pattern in patterns:
            if name not in found and re.search(pattern, text, re.IGNORECASE):
                found[name] = str(path.relative_to(root)) if root.is_dir() else path.name
    return [{"framework": key, "evidence_file": value} for key, value in sorted(found.items())]


def build_hypotheses(hits: list[Hit]) -> list[str]:
    categories = {hit.category for hit in hits}
    rules = {hit.rule for hit in hits}
    hypotheses: list[str] = []
    if "api-path" in rules or "absolute-url" in rules:
        hypotheses.append("Feed extracted API paths into Web/API audit; verify server-side authz with owned roles before claiming impact.")
    if "graphql-operation" in rules:
        hypotheses.append("Review GraphQL operations for field exposure, mutation authorization, introspection, and object-level authorization.")
    if "websocket" in rules:
        hypotheses.append("Map WebSocket channel join/send payloads; test only owned rooms/users for server-side room authorization.")
    if "signing-or-crypto" in rules:
        hypotheses.append("Trace signing/nonce/timestamp construction for replay or client-exposed secret assumptions; validate with synthetic requests.")
    if "secret" in categories:
        hypotheses.append("Triage secret-like literals for provider semantics and scope; rotate only confirmed in-scope active secrets.")
    if "source-map-ref" in rules:
        hypotheses.append("Check sourcemap availability and source disclosure impact inside authorization scope.")
    if "browser-storage" in rules or "auth-header" in rules:
        hypotheses.append("Trace token storage and request interceptors for leakage, missing CSRF boundaries, and client-only auth assumptions.")
    return hypotheses


def analyze(path: Path, max_files: int, max_size: int, complete: bool) -> dict:
    root = path.resolve()
    files = list(iter_files(root, max_files=max_files, max_size=max_size))
    hits: list[Hit] = []
    for item in files:
        hits.extend(scan_file(item, root if root.is_dir() else item.parent, complete))
    counts = Counter(hit.category for hit in hits)
    return {
        "artifact": str(root),
        "files_scanned": len(files),
        "summary": dict(sorted(counts.items())),
        "framework_hints": infer_framework(files, root if root.is_dir() else root.parent),
        "hits": [asdict(hit) for hit in hits],
        "hypotheses": build_hypotheses(hits),
        "limits": [
            "static extraction only",
            "endpoints are leads, not proof of reachable or vulnerable server behavior",
            "secret-like values require provider-aware confirmation",
        ],
    }


def print_markdown(payload: dict) -> None:
    print("# Wuyun JS Surface Extraction")
    print()
    print(f"- Artifact: `{payload['artifact']}`")
    print(f"- Files scanned: `{payload['files_scanned']}`")
    print()
    print("## Summary")
    if payload["summary"]:
        for category, count in payload["summary"].items():
            print(f"- `{category}`: {count}")
    else:
        print("- No JS/API surface hits found with bundled rules.")
    print()
    if payload["framework_hints"]:
        print("## Framework Hints")
        for item in payload["framework_hints"]:
            print(f"- `{item['framework']}` from `{item['evidence_file']}`")
        print()
    print("## Hits")
    for hit in payload["hits"][:200]:
        print(f"- `{hit['category']}` / `{hit['rule']}` at `{hit['file']}:{hit['line']}`: {hit['evidence']}")
    if len(payload["hits"]) > 200:
        print(f"- ... {len(payload['hits']) - 200} additional hits omitted; use `--json` for full output.")
    print()
    print("## Hypotheses")
    if payload["hypotheses"]:
        for item in payload["hypotheses"]:
            print(f"- {item}")
    else:
        print("- No prioritized hypotheses generated from current signals.")
    print()
    print("## Limits")
    for item in payload["limits"]:
        print(f"- {item}")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Passively extract JS bundle/API reverse-engineering leads.")
    parser.add_argument("path", help="JS file, sourcemap, HAR-like JSON, HTML, or directory")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    parser.add_argument("--complete-evidence", action="store_true", help="do not compact sensitive-looking evidence")
    parser.add_argument("--max-files", type=int, default=5000, help="maximum files to scan")
    parser.add_argument("--max-size", type=int, default=2_000_000, help="maximum file size in bytes")
    args = parser.parse_args(argv)

    path = Path(args.path).resolve()
    if not path.exists():
        print(f"error: path does not exist: {path}", file=sys.stderr)
        return 2
    payload = analyze(path, max_files=args.max_files, max_size=args.max_size, complete=args.complete_evidence)
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print_markdown(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
