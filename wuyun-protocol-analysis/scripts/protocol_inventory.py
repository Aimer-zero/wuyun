#!/usr/bin/env python3
"""Passive protocol inventory for Wuyun.

Reads local HAR/JSON/text/source files. It does not replay traffic.
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
from urllib.parse import urlparse


TEXT_EXTS = {".har", ".json", ".txt", ".log", ".js", ".ts", ".tsx", ".jsx", ".graphql", ".gql", ".proto", ".yaml", ".yml"}
SKIP_DIRS = {".git", "node_modules", ".wuyun", ".codex", ".claude", "dist", "build", "coverage"}


@dataclass
class Hit:
    protocol: str
    rule: str
    file: str
    line: int
    evidence: str
    confidence_hint: str


RULES: list[tuple[str, str, str, str]] = [
    ("websocket", "ws-url", r"\bwss?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+", "literal"),
    ("websocket", "websocket-constructor", r"\bnew\s+WebSocket\s*\(|WebSocket\(", "callsite"),
    ("socket.io", "socket-io", r"\bsocket\.io\b|\bio\s*\(|/socket\.io/", "callsite"),
    ("graphql", "operation", r"\b(?:query|mutation|subscription)\s+[A-Za-z_][A-Za-z0-9_]*\s*(?:\(|\{)", "operation"),
    ("graphql", "graphql-path", r"/graphql\b|graphql[\w.-]*\s*[:=]", "path"),
    ("sse", "eventsource", r"\bnew\s+EventSource\s*\(|text/event-stream", "callsite"),
    ("json-rpc", "jsonrpc", r"jsonrpc|\"method\"\s*:\s*\"[A-Za-z0-9_.:-]+\"", "rpc"),
    ("xml-rpc", "xmlrpc", r"xml-rpc|<methodCall>|<methodName>", "rpc"),
    ("grpc", "grpc", r"\bgrpc\b|application/grpc|grpc-web|\.proto\b", "grpc"),
    ("protobuf", "protobuf", r"\bproto3\b|protobuf|message\s+[A-Za-z_][A-Za-z0-9_]*|service\s+[A-Za-z_][A-Za-z0-9_]*", "schema"),
    ("multipart", "multipart", r"multipart/form-data|boundary=", "upload-protocol"),
    ("stream", "streaming", r"ReadableStream|TransformStream|chunked|application/stream\+json", "stream"),
]
COMPILED = [(proto, rule, re.compile(pattern, re.IGNORECASE), confidence) for proto, rule, pattern, confidence in RULES]


def iter_files(root: Path, max_files: int, max_size: int) -> Iterable[Path]:
    if root.is_file():
        if root.suffix.lower() in TEXT_EXTS:
            yield root
        return
    count = 0
    for dirpath, dirnames, filenames in os.walk(root):
        base = Path(dirpath)
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for filename in filenames:
            path = base / filename
            if path.suffix.lower() not in TEXT_EXTS:
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


def compact(value: str) -> str:
    text = " ".join(value.strip().split())
    text = re.sub(r"(https?://[^\s\"'<>?#]+)\?[^\"'<>\\\s]+", r"\1?<query-redacted>", text)
    text = re.sub(r"(?i)(authorization|cookie|token|secret|password)(\b\s*[:=]\s*)['\"]?[^'\"\s,;}]+", r"\1\2<compact-sensitive-value>", text)
    return text[:240] + "..." if len(text) > 240 else text


def header_map(headers: list[dict]) -> dict[str, str]:
    out = {}
    for header in headers or []:
        name = str(header.get("name", "")).lower()
        if name:
            out[name] = str(header.get("value", ""))
    return out


def scan_har(path: Path, root: Path) -> list[Hit]:
    hits: list[Hit] = []
    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return hits
    entries = payload.get("log", {}).get("entries", []) if isinstance(payload.get("log"), dict) else payload.get("entries", [])
    if not isinstance(entries, list):
        return hits
    rel = str(path.relative_to(root)) if root.is_dir() else path.name
    for index, entry in enumerate(entries, start=1):
        request = entry.get("request", {}) or {}
        response = entry.get("response", {}) or {}
        url = str(request.get("url", ""))
        parsed = urlparse(url)
        req_headers = header_map(request.get("headers", []))
        resp_headers = header_map(response.get("headers", []))
        mime = str((response.get("content", {}) or {}).get("mimeType", ""))
        combined = " ".join([url, mime, *req_headers.values(), *resp_headers.values()])
        for proto, rule, regex, confidence in COMPILED:
            if regex.search(combined):
                hits.append(Hit(proto, f"har-{rule}", rel, index, compact(f"{request.get('method', 'GET')} {parsed.netloc}{parsed.path}"), confidence))
    return hits


def scan_text(path: Path, root: Path) -> list[Hit]:
    hits: list[Hit] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return hits
    rel = str(path.relative_to(root)) if root.is_dir() else path.name
    for lineno, line in enumerate(text.splitlines(), start=1):
        for proto, rule, regex, confidence in COMPILED:
            if regex.search(line):
                if proto == "json-rpc" and re.search(
                    r"\"method\"\s*:\s*\"(?:GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\"",
                    line,
                    re.IGNORECASE,
                ):
                    continue
                hits.append(Hit(proto, rule, rel, lineno, compact(line), confidence))
    return hits


def hypotheses(protocols: set[str]) -> list[str]:
    out: list[str] = []
    if "websocket" in protocols or "socket.io" in protocols:
        out.append("Model connect/join/send flows and verify server-side room/channel authorization with owned accounts.")
    if "graphql" in protocols:
        out.append("Inventory query/mutation/subscription operations and validate field/object authorization server-side.")
    if "json-rpc" in protocols or "xml-rpc" in protocols:
        out.append("Review exposed RPC methods, parameter trust, and role checks before replay.")
    if "grpc" in protocols or "protobuf" in protocols:
        out.append("Map protobuf services/messages and verify authn/authz on callable methods.")
    if "sse" in protocols or "stream" in protocols:
        out.append("Check stream subscription authorization and cross-tenant event isolation with synthetic records.")
    if "multipart" in protocols:
        out.append("Feed multipart/upload surfaces into file handling review for path, content-type, and parser risks.")
    return out


def analyze(path: Path, max_files: int, max_size: int) -> dict:
    root = path.resolve()
    files = list(iter_files(root, max_files, max_size))
    hits: list[Hit] = []
    for item in files:
        if item.suffix.lower() == ".har":
            hits.extend(scan_har(item, root if root.is_dir() else item.parent))
            continue
        hits.extend(scan_text(item, root if root.is_dir() else item.parent))
    protocols = {hit.protocol for hit in hits}
    return {
        "artifact": str(root),
        "files_scanned": len(files),
        "summary": dict(Counter(hit.protocol for hit in hits).most_common()),
        "hits": [asdict(hit) for hit in hits],
        "hypotheses": hypotheses(protocols),
        "limits": [
            "passive inventory only; no captured traffic replayed",
            "protocol names and operations are leads, not proof of callable or vulnerable behavior",
            "validate with owned accounts, synthetic records, and explicit scope",
        ],
    }


def print_markdown(payload: dict) -> None:
    print("# Wuyun Protocol Inventory")
    print()
    print(f"- Artifact: `{payload['artifact']}`")
    print(f"- Files scanned: `{payload['files_scanned']}`")
    print()
    print("## Protocol Summary")
    if payload["summary"]:
        for proto, count in payload["summary"].items():
            print(f"- `{proto}`: {count}")
    else:
        print("- No configured protocol signals found.")
    print()
    print("## Hits")
    for hit in payload["hits"][:180]:
        print(f"- `{hit['protocol']}` / `{hit['rule']}` at `{hit['file']}:{hit['line']}`: {hit['evidence']}")
    if len(payload["hits"]) > 180:
        print(f"- ... {len(payload['hits']) - 180} additional hits omitted; use `--json` for full output.")
    print()
    print("## Hypotheses")
    if payload["hypotheses"]:
        for item in payload["hypotheses"]:
            print(f"- {item}")
    else:
        print("- No protocol-specific hypotheses generated.")
    print()
    print("## Limits")
    for item in payload["limits"]:
        print(f"- {item}")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Passively inventory protocols from HAR/text/source artifacts.")
    parser.add_argument("path", help="HAR, proxy export, source file, or directory")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    parser.add_argument("--max-files", type=int, default=5000)
    parser.add_argument("--max-size", type=int, default=2_000_000)
    args = parser.parse_args(argv)

    path = Path(args.path).resolve()
    if not path.exists():
        print(f"error: path does not exist: {path}", file=sys.stderr)
        return 2
    payload = analyze(path, args.max_files, args.max_size)
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print_markdown(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
