#!/usr/bin/env python3
"""Passive Web/API route extractor.

Scans local source files for common route declarations. It does not execute code,
import projects, or contact services. Results are leads for manual verification.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", "target", "__pycache__", ".next", ".nuxt", ".venv", "venv"}
TEXT_EXTS = {".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".kt", ".go", ".rb", ".php", ".cs", ".rs", ".vue", ".yaml", ".yml", ".json"}

PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    ("express", "js", re.compile(r"\b(?:app|router)\s*\.\s*(get|post|put|patch|delete|all|use)\s*\(\s*['\"]([^'\"]+)", re.I)),
    ("fastify", "js", re.compile(r"\bfastify\s*\.\s*(get|post|put|patch|delete|all)\s*\(\s*['\"]([^'\"]+)", re.I)),
    ("nestjs", "ts", re.compile(r"@(Get|Post|Put|Patch|Delete|All)\s*\(\s*['\"]?([^'\")]+)?", re.I)),
    ("fastapi", "py", re.compile(r"@(?:app|router)\s*\.\s*(get|post|put|patch|delete|api_route)\s*\(\s*['\"]([^'\"]+)", re.I)),
    ("flask", "py", re.compile(r"@(?:app|bp|blueprint)\s*\.\s*route\s*\(\s*['\"]([^'\"]+)", re.I)),
    ("django", "py", re.compile(r"\b(?:path|re_path|url)\s*\(\s*['\"]([^'\"]+)", re.I)),
    ("spring", "java", re.compile(r"@(GetMapping|PostMapping|PutMapping|PatchMapping|DeleteMapping|RequestMapping)\b(?:\s*\(([^)]*)\))?", re.I)),
    ("laravel", "php", re.compile(r"\bRoute::(get|post|put|patch|delete|any|match)\s*\(\s*['\"]([^'\"]+)", re.I)),
    ("go-gin", "go", re.compile(r"\b(?:router|r|group)\s*\.\s*(GET|POST|PUT|PATCH|DELETE|Any|Handle)\s*\(\s*`?['\"]?([^'\"`,)]+)", re.I)),
)

SENSITIVE_WORDS = re.compile(r"(?i)admin|internal|debug|export|import|upload|download|delete|role|permission|tenant|account|webhook|callback|redirect|url|file|path")


@dataclass
class RouteLead:
    framework: str
    method: str
    path: str
    file: str
    line: int
    evidence: str
    priority: str


def iter_files(root: Path, max_files: int, max_size: int) -> Iterable[Path]:
    count = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for filename in filenames:
            path = Path(dirpath) / filename
            try:
                if path.suffix.lower() not in TEXT_EXTS and path.name not in {"Dockerfile", "routes.rb"}:
                    continue
                if path.stat().st_size > max_size:
                    continue
            except OSError:
                continue
            count += 1
            if count > max_files:
                return
            yield path


def clean_evidence(line: str) -> str:
    line = " ".join(line.strip().split())
    return line[:177] + "..." if len(line) > 180 else line


def priority(path: str, evidence: str, method: str) -> str:
    if method.upper() in {"DELETE", "PUT", "PATCH", "POST"} and SENSITIVE_WORDS.search(path + " " + evidence):
        return "high"
    if SENSITIVE_WORDS.search(path + " " + evidence):
        return "medium"
    return "review"


def nextjs_route_from_path(path: Path, root: Path) -> RouteLead | None:
    rel = path.relative_to(root)
    parts = rel.parts
    if rel.suffix.lower() not in {".js", ".ts"}:
        return None
    if "pages" in parts and "api" in parts:
        idx = parts.index("api")
        route_parts = list(parts[idx + 1:])
        route_parts[-1] = Path(route_parts[-1]).stem
        route = "/api/" + "/".join(route_parts).replace("index", "").rstrip("/")
        return RouteLead("nextjs-pages", "ANY", route or "/api", str(rel), 1, "Next.js pages/api file", priority(route, "", "ANY"))
    if rel.name in {"route.ts", "route.js"} and "app" in parts:
        idx = parts.index("app")
        route_parts = list(parts[idx + 1:-1])
        route = "/" + "/".join(route_parts).replace("(api)/", "")
        return RouteLead("nextjs-app", "ANY", route or "/", str(rel), 1, "Next.js app route file", priority(route, "", "ANY"))
    return None


def extract(root: Path, max_files: int, max_size: int) -> list[RouteLead]:
    leads: list[RouteLead] = []
    for path in iter_files(root, max_files, max_size):
        next_lead = nextjs_route_from_path(path, root)
        if next_lead:
            leads.append(next_lead)
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(path.relative_to(root))
        for lineno, line in enumerate(text.splitlines(), start=1):
            for framework, _lang, regex in PATTERNS:
                match = regex.search(line)
                if not match:
                    continue
                groups = match.groups()
                if framework in {"flask", "django"}:
                    method, route = "ANY", groups[0]
                elif framework == "spring":
                    method = groups[0].replace("Mapping", "").upper() or "ANY"
                    route_match = re.search(r"['\"]([^'\"]+)['\"]", groups[1] or "")
                    route = route_match.group(1) if route_match else "<annotation-path>"
                elif framework == "nestjs" and len(groups) >= 2:
                    method, route = groups[0].upper(), (groups[1] or "/").strip()
                else:
                    method, route = groups[0].upper(), groups[1]
                evidence = clean_evidence(line)
                leads.append(RouteLead(framework, method, route, rel, lineno, evidence, priority(route, evidence, method)))
    return leads


def print_markdown(leads: list[RouteLead]) -> None:
    print("# Web/API Route Extraction")
    print()
    print(f"- Route leads: `{len(leads)}`")
    print("- Execution: passive source scan only")
    print()
    if not leads:
        print("No configured route patterns found. Continue manual framework review.")
        return
    print("| Priority | Method | Path | Framework | Location | Evidence |")
    print("|---|---|---|---|---|---|")
    for lead in sorted(leads, key=lambda x: (x.priority != "high", x.priority != "medium", x.file, x.line)):
        print(f"| {lead.priority} | `{lead.method}` | `{lead.path}` | {lead.framework} | `{lead.file}:{lead.line}` | `{lead.evidence}` |")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Passively extract Web/API route leads from source.")
    parser.add_argument("path", nargs="?", default=".", help="repository root")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    parser.add_argument("--max-files", type=int, default=5000)
    parser.add_argument("--max-size", type=int, default=1_000_000)
    args = parser.parse_args(argv)
    root = Path(args.path).resolve()
    if not root.exists():
        print(f"error: path does not exist: {root}", file=sys.stderr)
        return 2
    leads = extract(root, args.max_files, args.max_size)
    if args.json:
        print(json.dumps({"routes": [asdict(lead) for lead in leads]}, ensure_ascii=False, indent=2))
    else:
        print_markdown(leads)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
