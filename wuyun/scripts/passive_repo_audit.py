#!/usr/bin/env python3
"""Passive repository audit helper for Wuyun.

Scans local text/source files only. It does not execute project code, install
packages, call network services, or print secret values. Results are review
leads for source → boundary → sink tracing, not confirmed vulnerabilities.
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
    ".git", ".hg", ".svn", ".idea", ".vscode", ".claude", ".codex", ".wuyun",
    "node_modules", "vendor", "dist", "build", "target", "__pycache__", ".pytest_cache",
    ".mypy_cache", ".tox", ".venv", "venv", "env", "coverage", ".next", ".nuxt",
    "out", "tmp", "temp", "logs",
}
ALLOW_HIDDEN_DIRS = {".github", ".well-known"}
TEXT_EXTS = {
    ".py", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".java", ".kt", ".go", ".rs",
    ".rb", ".php", ".cs", ".c", ".cc", ".cpp", ".h", ".hpp", ".scala", ".swift",
    ".m", ".mm", ".html", ".htm", ".vue", ".svelte", ".xml", ".yaml", ".yml",
    ".json", ".toml", ".ini", ".conf", ".properties", ".env", ".sh", ".bash", ".zsh",
    ".sql", ".md", ".graphql", ".gql", ".proto", ".tf", ".dockerfile",
}
MANIFEST_NAMES = {
    "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "requirements.txt",
    "pyproject.toml", "Pipfile", "poetry.lock", "pom.xml", "build.gradle", "build.gradle.kts",
    "settings.gradle", "go.mod", "go.sum", "Cargo.toml", "Cargo.lock", "composer.json",
    "composer.lock", "Gemfile", "Gemfile.lock", "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    "Makefile", ".env", ".env.local", ".env.example", "config.yml", "config.yaml",
    "openapi.yaml", "openapi.yml", "swagger.yaml", "swagger.yml", "swagger.json",
}
DOC_EXTS = {".md", ".txt", ".rst"}


@dataclass
class Hit:
    category: str
    rule: str
    file: str
    line: int
    evidence: str
    severity_hint: str = "review"
    confidence_hint: str = "pattern"


# category, rule, regex, severity
RULES: list[tuple[str, str, str, str]] = [
    ("route", "express-route", r"\b(?:app|router)\s*\.\s*(?:get|post|put|patch|delete|all|use)\s*\(\s*['\"]([^'\"]+)", "info"),
    ("route", "fastapi-route", r"@(?:app|router)\s*\.\s*(?:get|post|put|patch|delete|api_route)\s*\(\s*['\"]([^'\"]+)", "info"),
    ("route", "flask-route", r"@(?:app|bp|blueprint)\s*\.\s*route\s*\(\s*['\"]([^'\"]+)", "info"),
    ("route", "django-url", r"\b(?:path|re_path|url)\s*\(\s*['\"]([^'\"]+)", "info"),
    ("route", "spring-route", r"@(RequestMapping|GetMapping|PostMapping|PutMapping|PatchMapping|DeleteMapping)\b(?:\s*\([^)]*\))?", "info"),
    ("route", "laravel-route", r"\bRoute::(?:get|post|put|patch|delete|any|match)\s*\(\s*['\"]([^'\"]+)", "info"),
    ("route", "openapi-path", r"^\s*/[^:\s]+:\s*$", "info"),
    ("sink", "command-exec", r"\b(?:exec|spawn|execSync|spawnSync|child_process\.|os\.system|subprocess\.(?:Popen|run|call|check_output)|Runtime\.getRuntime\(\)\.exec|ProcessBuilder\s*\()\b", "high"),
    ("sink", "dynamic-code-exec", r"\b(?:eval|Function\s*\(|vm\.runIn(?:New)?Context|exec\s*\(|pickle\.loads|marshal\.loads|yaml\.load\s*\(|new ScriptEngineManager|ScriptEngine\.eval)\b", "high"),
    ("sink", "sql-raw", r"\b(?:rawQuery|createNativeQuery|executeQuery|executescript|cursor\.execute|db\.query|sequelize\.query|knex\.raw|\$queryRawUnsafe|prepareStatement\s*\(\s*\w+\s*\+)", "medium"),
    ("sink", "nosql-raw", r"\b(?:\$where|mapReduce|collection\.find\s*\(|Model\.find\s*\(\s*req\.|where\s*:\s*req\.)", "medium"),
    ("sink", "file-write-or-read", r"\b(?:open|readFile|writeFile|createReadStream|createWriteStream|sendFile|download|ZipFile|extractall|tarfile\.open)\s*\(", "medium"),
    ("sink", "ssrf-capable-fetch", r"\b(?:requests\.(?:get|post|put|delete)|urllib\.request\.urlopen|axios\.|fetch\s*\(|http\.get|https\.get|RestTemplate|WebClient|curl_exec)\b", "medium"),
    ("sink", "template-render", r"\b(?:render_template_string|Template\s*\(|jinja2\.Template|dangerouslySetInnerHTML|innerHTML\s*=|outerHTML\s*=|v-html=|Handlebars\.compile)\b", "medium"),
    ("sink", "unsafe-deserialization", r"\b(?:pickle\.loads|yaml\.load\s*\(|ObjectInputStream|readObject\s*\(|unserialize\s*\(|JSON\.parseObject\s*\([^,]+,\s*Object\.class)\b", "high"),
    ("auth", "auth-todo-or-bypass", r"(?i)\b(?:todo|fixme|hack|temporary|bypass|skip auth|no auth|disable auth|admin only|permission|authorize|authorise|tenant|ownership)\b", "review"),
    ("auth", "jwt-unverified", r"(?i)\b(?:verify\s*[:=]\s*false|ignoreExpiration\s*[:=]\s*true|alg\s*[:=]\s*none|decode\s*\([^)]*jwt)", "high"),
    ("config", "debug-enabled", r"(?i)\b(?:debug\s*[:=]\s*true|development\s*[:=]\s*true|NODE_ENV\s*[:=]\s*development|FLASK_DEBUG\s*=\s*1|APP_DEBUG\s*=\s*true)\b", "medium"),
    ("config", "wide-cors", r"(?i)(Access-Control-Allow-Origin\s*[:=]\s*['\"]?\*|cors\s*\(\s*\{|allowedOrigins\s*=\s*['\"]\*)", "medium"),
    ("crypto", "weak-crypto", r"(?i)\b(?:md5|sha1|DES|ECB|Math\.random\s*\(|Random\s*\(|createHash\s*\(\s*['\"]md5|createCipher\s*\()\b", "review"),
    ("secret", "secret-like-assignment", r"(?i)\b(?:api[_-]?key|secret|token|password|passwd|private[_-]?key|access[_-]?key|auth[_-]?key)\b\s*[:=]\s*['\"]?([^'\"\s]{8,})", "high"),
    ("secret", "private-key-block", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PRIVATE )?PRIVATE KEY-----", "high"),
]

COMPILED = [(cat, rule, re.compile(pattern), severity) for cat, rule, pattern, severity in RULES]

FRAMEWORK_HINTS: list[tuple[str, str, str]] = [
    ("node", "express", r"\bexpress\b"),
    ("node", "nextjs", r"\bnext\b|next.config"),
    ("node", "nestjs", r"@nestjs/"),
    ("node", "koa", r"\bkoa\b"),
    ("node", "fastify", r"\bfastify\b"),
    ("python", "django", r"\bdjango\b|DJANGO_SETTINGS_MODULE"),
    ("python", "flask", r"\bflask\b|Flask\s*\("),
    ("python", "fastapi", r"\bfastapi\b|FastAPI\s*\("),
    ("java", "spring", r"spring-boot|org\.springframework|@SpringBootApplication"),
    ("php", "laravel", r"laravel/framework|Illuminate\\"),
    ("go", "gin", r"github\.com/gin-gonic/gin"),
    ("go", "echo", r"github\.com/labstack/echo"),
    ("rust", "actix", r"actix-web"),
]


def is_probably_text(path: Path) -> bool:
    return path.suffix.lower() in TEXT_EXTS or path.name in MANIFEST_NAMES or path.name.endswith(".env")


def is_doc(path: Path) -> bool:
    return path.suffix.lower() in DOC_EXTS or any(part in {"docs", "doc", "examples"} for part in path.parts)


def is_excluded(rel: Path, excludes: list[str]) -> bool:
    rel_s = rel.as_posix()
    return any(rel_s == item or rel_s.startswith(item.rstrip("/") + "/") for item in excludes)


def iter_files(root: Path, max_files: int, max_size: int, code_only: bool, excludes: list[str]) -> Iterable[Path]:
    count = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d for d in dirnames
            if d not in SKIP_DIRS and (not d.startswith(".") or d in ALLOW_HIDDEN_DIRS)
        ]
        for filename in filenames:
            path = Path(dirpath) / filename
            try:
                rel_path = path.relative_to(root)
                if is_excluded(rel_path, excludes):
                    continue
                if not is_probably_text(path):
                    continue
                if code_only and is_doc(rel_path):
                    continue
                if path.stat().st_size > max_size:
                    continue
            except OSError:
                continue
            count += 1
            if count > max_files:
                return
            yield path


def format_evidence(category: str, line: str, complete: bool = False) -> str:
    """Format one evidence line without leaking secret values.

    `complete=True` preserves full non-secret context for private remediation
    reports, but secret-like values and private key blocks are still redacted.
    """
    compact = " ".join(line.strip().split())
    compact = re.sub(
        r"(?i)(api[_-]?key|secret|token|password|passwd|private[_-]?key|access[_-]?key|auth[_-]?key)(\b\s*[:=]\s*)['\"]?[^'\"\s]+['\"]?",
        r"\1\2<redacted-sensitive-value>",
        compact,
    )
    compact = re.sub(r"-----BEGIN [^-]+PRIVATE KEY-----", "<redacted private key block>", compact)
    if not complete and len(compact) > 180:
        compact = compact[:177] + "..."
    return compact


def adjusted_severity(path: Path, category: str, severity: str) -> tuple[str, str]:
    if category in {"secret", "config"}:
        return severity, "pattern"
    if is_doc(path):
        return "doc-review", "documentation-example"
    return severity, "pattern"


def is_own_rule_definition(path: Path, line: str) -> bool:
    if path.name not in {"passive_repo_audit.py", "extract_js_surface.py"}:
        return False
    stripped = line.lstrip()
    if path.name == "passive_repo_audit.py":
        return (
            stripped.startswith('("')
            or "hypotheses.append" in stripped
            or "rules" in stripped and "command-exec" in stripped
            or "auth-todo-or-bypass" in stripped and "rules" in stripped
        )
    return stripped.startswith('("') or stripped.startswith("('") or "hypotheses.append" in stripped


def scan_file(path: Path, root: Path, complete_evidence: bool = False) -> list[Hit]:
    hits: list[Hit] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return hits
    rel_path = path.relative_to(root)
    rel = str(rel_path)
    for lineno, line in enumerate(text.splitlines(), start=1):
        if is_own_rule_definition(path, line):
            continue
        for category, rule, regex, severity in COMPILED:
            if regex.search(line):
                sev, conf = adjusted_severity(rel_path, category, severity)
                hits.append(Hit(category, rule, rel, lineno, format_evidence(category, line, complete=complete_evidence), sev, conf))
    # File-path based framework routes.
    parts = rel_path.parts
    if "pages" in parts and rel_path.parent.name == "api" and rel_path.suffix in {".js", ".ts"}:
        hits.append(Hit("route", "nextjs-pages-api", rel, 1, "Next.js pages/api route file", "info", "file-layout"))
    if rel_path.name == "route.ts" or rel_path.name == "route.js":
        if "app" in parts:
            hits.append(Hit("route", "nextjs-app-route", rel, 1, "Next.js app router route file", "info", "file-layout"))
    return hits


def language_from_ext(ext: str) -> str:
    return {
        ".py": "Python", ".js": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript",
        ".jsx": "React/JSX", ".ts": "TypeScript", ".tsx": "React/TSX", ".java": "Java",
        ".kt": "Kotlin", ".go": "Go", ".rs": "Rust", ".rb": "Ruby", ".php": "PHP",
        ".cs": "C#", ".c": "C/C++", ".cc": "C/C++", ".cpp": "C/C++", ".h": "C/C++",
        ".hpp": "C/C++", ".swift": "Swift", ".vue": "Vue", ".svelte": "Svelte",
    }.get(ext.lower(), ext.lower().lstrip(".") or "other")


def detect_frameworks(files: list[Path], root: Path) -> list[dict]:
    evidence: list[dict] = []
    for path in files:
        if path.name == "passive_repo_audit.py":
            continue
        if path.name not in MANIFEST_NAMES and path.suffix.lower() not in {".py", ".js", ".ts", ".java", ".go", ".php"}:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")[:200_000]
        except OSError:
            continue
        for ecosystem, framework, pattern in FRAMEWORK_HINTS:
            if re.search(pattern, text, re.IGNORECASE):
                evidence.append({"ecosystem": ecosystem, "framework": framework, "file": str(path.relative_to(root))})
    dedup: dict[tuple[str, str], dict] = {}
    for item in evidence:
        dedup.setdefault((item["ecosystem"], item["framework"]), item)
    return sorted(dedup.values(), key=lambda x: (x["ecosystem"], x["framework"]))


def build_hypotheses(hits: list[Hit]) -> list[str]:
    rules = {h.rule for h in hits if h.confidence_hint != "documentation-example"}
    hypotheses: list[str] = []
    if {"command-exec", "ssrf-capable-fetch"} & rules:
        hypotheses.append("Trace user-controlled input into command execution or outbound fetch sinks; validate with harmless local/synthetic indicators only.")
    if {"sql-raw", "nosql-raw"} & rules:
        hypotheses.append("Check whether raw database calls use parameter binding, operator allowlists, and server-side authorization before query construction.")
    if "file-write-or-read" in rules:
        hypotheses.append("Review path canonicalization, upload/extraction handling, and whether user-controlled filenames can cross directory boundaries.")
    if "template-render" in rules:
        hypotheses.append("Review template/HTML rendering sinks for context-aware escaping and post-sanitization transformations.")
    if "unsafe-deserialization" in rules:
        hypotheses.append("Confirm whether untrusted data reaches unsafe deserialization or polymorphic parsing; prefer safe local fixtures for validation.")
    if {"secret-like-assignment", "private-key-block"} & rules:
        hypotheses.append("Confirm whether secret-like values are real, in-scope, and active; rotate if exposed, and include exact values only through an approved secure channel, not in tool output.")
    if {"auth-todo-or-bypass", "jwt-unverified"} & rules:
        hypotheses.append("Prioritize comments/branches and token handling that mention auth bypass, permissions, tenants, ownership, or unverified JWTs.")
    if {"debug-enabled", "wide-cors", "weak-crypto"} & rules:
        hypotheses.append("Review insecure configuration and crypto defaults in runtime deployment context before reporting.")
    return hypotheses


def audit(root: Path, max_files: int, max_size: int, code_only: bool, excludes: list[str], complete_evidence: bool = False) -> dict:
    root = root.resolve()
    files = list(iter_files(root, max_files=max_files, max_size=max_size, code_only=code_only, excludes=excludes))
    language_counts = Counter(language_from_ext(p.suffix) for p in files)
    manifests = sorted(str(p.relative_to(root)) for p in files if p.name in MANIFEST_NAMES)
    hits: list[Hit] = []
    for path in files:
        hits.extend(scan_file(path, root, complete_evidence=complete_evidence))
    hits_by_category = Counter(h.category for h in hits)
    hits_by_rule = Counter(h.rule for h in hits)
    routes = [h for h in hits if h.category == "route"]
    interesting = [h for h in hits if h.category != "route"]
    return {
        "root": str(root),
        "scanned_files": len(files),
        "code_only": code_only,
        "excludes": excludes,
        "complete_evidence": complete_evidence,
        "language_counts": dict(language_counts.most_common()),
        "manifests": manifests[:200],
        "framework_hints": detect_frameworks(files, root),
        "hit_counts": dict(hits_by_category.most_common()),
        "rule_counts": dict(hits_by_rule.most_common()),
        "routes": [asdict(h) for h in routes[:300]],
        "review_leads": [asdict(h) for h in interesting[:500]],
        "hypotheses": build_hypotheses(interesting),
        "truncated": len(files) >= max_files,
    }


def print_markdown(result: dict) -> None:
    print("# Wuyun Passive Repository Audit")
    print()
    print(f"- Root: `{result['root']}`")
    print(f"- Scanned files: `{result['scanned_files']}`")
    print(f"- Code-only mode: `{result['code_only']}`")
    if result.get("excludes"):
        print("- Excludes: " + ", ".join(f"`{x}`" for x in result["excludes"]))
    print(f"- Truncated by max-files: `{result['truncated']}`")
    print()

    print("## Languages")
    if result["language_counts"]:
        for lang, count in result["language_counts"].items():
            print(f"- {lang}: {count}")
    else:
        print("- No supported text/source files found.")
    print()

    print("## Manifests / Config Entry Points")
    if result["manifests"]:
        for item in result["manifests"][:80]:
            print(f"- `{item}`")
        if len(result["manifests"]) > 80:
            print(f"- ... {len(result['manifests']) - 80} more")
    else:
        print("- None found in scanned files.")
    print()

    print("## Framework Hints")
    if result["framework_hints"]:
        for item in result["framework_hints"]:
            print(f"- {item['ecosystem']}/{item['framework']} via `{item['file']}`")
    else:
        print("- No configured framework hints found.")
    print()

    print("## Route / Endpoint Leads")
    if result["routes"]:
        for hit in result["routes"][:100]:
            print(f"- `{hit['file']}:{hit['line']}` [{hit['rule']}/{hit['confidence_hint']}] {hit['evidence']}")
        if len(result["routes"]) > 100:
            print(f"- ... {len(result['routes']) - 100} more")
    else:
        print("- No common route patterns found.")
    print()

    print("## Security Review Leads")
    if result["review_leads"]:
        for hit in result["review_leads"][:140]:
            print(f"- `{hit['file']}:{hit['line']}` [{hit['severity_hint']}/{hit['rule']}/{hit['confidence_hint']}] {hit['evidence']}")
        if len(result["review_leads"]) > 140:
            print(f"- ... {len(result['review_leads']) - 140} more")
    else:
        print("- No configured risky patterns found. This is not proof of absence.")
    print()

    print("## Initial Hypotheses")
    if result["hypotheses"]:
        for item in result["hypotheses"]:
            print(f"- {item}")
    else:
        print("- No hypotheses generated from configured patterns. Continue manual architecture review.")
    print()
    print("_Note: This is passive triage. Confirm findings by tracing source → trust boundary → sink and collecting minimal safe evidence._")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Passive local repository audit for Wuyun.")
    parser.add_argument("path", nargs="?", default=".", help="repository root")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of Markdown")
    parser.add_argument("--max-files", type=int, default=5000, help="maximum files to scan")
    parser.add_argument("--max-size", type=int, default=512_000, help="maximum file size in bytes")
    parser.add_argument("--code-only", action="store_true", help="skip documentation/example files to reduce false positives")
    parser.add_argument("--exclude", action="append", default=[], help="relative file or directory prefix to skip; may be repeated")
    parser.add_argument("--complete-evidence", action="store_true", help="preserve full non-secret context; secret-like values remain redacted")
    args = parser.parse_args(argv)

    root = Path(args.path)
    if not root.exists() or not root.is_dir():
        print(f"error: not a directory: {root}", file=sys.stderr)
        return 2

    result = audit(root, args.max_files, args.max_size, args.code_only, args.exclude, complete_evidence=args.complete_evidence)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print_markdown(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
