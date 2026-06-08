#!/usr/bin/env python3
"""Passive AI/LLM attack-surface extractor for Wuyun."""
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


TEXT_EXTS = {".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".go", ".rb", ".php", ".yaml", ".yml", ".json", ".md", ".txt", ".toml"}
SKIP_DIRS = {".git", "node_modules", ".wuyun", ".codex", ".claude", "dist", "build", "coverage"}


@dataclass
class Hit:
    category: str
    rule: str
    file: str
    line: int
    evidence: str
    confidence_hint: str


RULES = [
    ("llm", "llm-provider", r"(?i)\b(openai|anthropic|gemini|bedrock|azure_openai|chat.completions|responses\.create|messages\.create)\b", "provider"),
    ("prompt", "prompt-template", r"(?i)\b(system_prompt|developer_prompt|prompt_template|instructions|role\s*:\s*['\"]system)\b", "prompt"),
    ("rag", "rag-vector", r"(?i)\b(vectorstore|embedding|retriever|similarity_search|pinecone|weaviate|qdrant|chroma|faiss|milvus)\b", "rag"),
    ("agent-tool", "file-tool", r"(?i)\b(read_file|write_file|open\(|fs\.|path\.join|workspace|artifact)\b", "tool"),
    ("agent-tool", "http-tool", r"(?i)\b(fetch|requests\.get|axios|http_tool|browser|urlopen)\b", "tool"),
    ("agent-tool", "shell-tool", r"(?i)\b(subprocess|execSync|child_process|shell|terminal|bash)\b", "tool"),
    ("memory", "memory", r"(?i)\b(memory|conversation_store|chat_history|long[-_ ]term|remember)\b", "memory"),
    ("output", "output-sink", r"(?i)\b(markdown|html|innerHTML|email|slack|webhook|ticket|comment)\b", "sink"),
]
COMPILED = [(cat, rule, re.compile(pattern), confidence) for cat, rule, pattern, confidence in RULES]


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


def compact(line: str) -> str:
    text = " ".join(line.strip().split())
    text = re.sub(r"(?i)(api[_-]?key|token|secret|password)(\b\s*[:=]\s*)[^'\"\s,;}]+", r"\1\2<compact-sensitive-value>", text)
    return text[:220] + "..." if len(text) > 220 else text


def analyze(path: Path, max_files: int, max_size: int) -> dict:
    root = path.resolve()
    hits: list[Hit] = []
    files = list(iter_files(root, max_files, max_size))
    for item in files:
        try:
            text = item.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(item.relative_to(root)) if root.is_dir() else item.name
        for lineno, line in enumerate(text.splitlines(), start=1):
            for category, rule, regex, confidence in COMPILED:
                if regex.search(line):
                    hits.append(Hit(category, rule, rel, lineno, compact(line), confidence))
    categories = {hit.category for hit in hits}
    hypotheses = []
    if "rag" in categories:
        hypotheses.append("Review writable RAG sources, source provenance, tenant isolation, and retrieved-text instruction boundaries.")
    if "agent-tool" in categories:
        hypotheses.append("Review tool allowlists, path/URL canonicalization, shell argument handling, and approval boundaries.")
    if "prompt" in categories:
        hypotheses.append("Review prompt assembly and whether untrusted content can override system/developer instructions.")
    if "output" in categories:
        hypotheses.append("Review model output sinks for HTML/script injection, webhook actions, and untrusted markdown rendering.")
    return {
        "artifact": str(root),
        "files_scanned": len(files),
        "summary": dict(Counter(hit.category for hit in hits).most_common()),
        "hits": [asdict(hit) for hit in hits],
        "hypotheses": hypotheses,
        "limits": ["passive source/config triage only", "does not execute model/tool workflows"],
    }


def print_markdown(payload: dict) -> None:
    print("# Wuyun AI Surface Audit")
    print()
    print(f"- Artifact: `{payload['artifact']}`")
    print(f"- Files scanned: `{payload['files_scanned']}`")
    print("## Summary")
    for key, value in payload["summary"].items():
        print(f"- `{key}`: {value}")
    if not payload["summary"]:
        print("- No configured AI/LLM signals found.")
    print("## Hits")
    for hit in payload["hits"][:180]:
        print(f"- `{hit['category']}` / `{hit['rule']}` at `{hit['file']}:{hit['line']}`: {hit['evidence']}")
    print("## Hypotheses")
    for item in payload["hypotheses"]:
        print(f"- {item}")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Passively extract AI/LLM attack surface.")
    parser.add_argument("path")
    parser.add_argument("--json", action="store_true")
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
