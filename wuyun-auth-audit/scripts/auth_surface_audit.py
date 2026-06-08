#!/usr/bin/env python3
"""Passive auth/session surface extractor for Wuyun."""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Iterable


TEXT_EXTS = {".har", ".http", ".txt", ".log", ".js", ".ts", ".py", ".java", ".go", ".rb", ".php", ".yaml", ".yml", ".json", ".md"}
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
    ("jwt", "jwt-looking-token", r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*", "token-shape"),
    ("oauth", "oauth-params", r"(?i)\b(?:redirect_uri|response_type|client_id|code_challenge|code_verifier|state|nonce|scope)=?", "flow-signal"),
    ("oidc", "oidc", r"(?i)\b(?:openid|id_token|userinfo|jwks_uri|issuer|authorization_endpoint|token_endpoint)\b", "flow-signal"),
    ("saml", "saml", r"(?i)\b(?:SAMLRequest|SAMLResponse|RelayState|AssertionConsumerService|NameID|SignatureValue)\b", "flow-signal"),
    ("cookie", "set-cookie", r"(?i)\bset-cookie\s*:\s*(.+)", "header"),
    ("session", "session", r"(?i)\b(?:sessionid|sid|csrf|xsrf|remember_me|refresh_token)\b", "session-signal"),
    ("tenant", "tenant-authz", r"(?i)\b(?:tenant|orgId|organizationId|workspaceId|accountId|roleId|permission|ownerId)\b", "authz-signal"),
]
COMPILED = [(cat, rule, re.compile(pattern), confidence) for cat, rule, pattern, confidence in RULES]


def iter_files(root: Path, max_files: int, max_size: int) -> Iterable[Path]:
    if root.is_file():
        if root.suffix.lower() in TEXT_EXTS or root.name in {"headers", "response"}:
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


def compact(text: str) -> str:
    text = " ".join(text.strip().split())
    text = re.sub(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*", "<compact-jwt>", text)
    text = re.sub(r"(?i)(authorization|cookie|token|secret|password)(\b\s*[:=]\s*)[^'\"\s,;}]+", r"\1\2<compact-sensitive-value>", text)
    return text[:240] + "..." if len(text) > 240 else text


def cookie_risks(set_cookie_value: str) -> list[str]:
    risks = []
    cookie = SimpleCookie()
    try:
        cookie.load(set_cookie_value)
    except Exception:
        return ["cookie-parse-failed"]
    lower = set_cookie_value.lower()
    if "secure" not in lower:
        risks.append("missing-secure")
    if "httponly" not in lower:
        risks.append("missing-httponly")
    if "samesite" not in lower:
        risks.append("missing-samesite")
    if "domain=" in lower:
        risks.append("explicit-domain-review-scope")
    return risks


def scan_file(path: Path, root: Path) -> tuple[list[Hit], list[str]]:
    hits = []
    risks = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return hits, risks
    rel = str(path.relative_to(root)) if root.is_dir() else path.name
    for lineno, line in enumerate(text.splitlines(), start=1):
        for category, rule, regex, confidence in COMPILED:
            match = regex.search(line)
            if not match:
                continue
            hits.append(Hit(category, rule, rel, lineno, compact(match.group(0)), confidence))
            if rule == "set-cookie":
                risks.extend(cookie_risks(match.group(1)))
    return hits, risks


def hypotheses(categories: set[str], risks: list[str]) -> list[str]:
    out = []
    if "oauth" in categories or "oidc" in categories:
        out.append("Review redirect_uri exact matching, state/nonce binding, PKCE, issuer/audience, and key selection.")
    if "saml" in categories:
        out.append("Review XML signature validation, signed assertion/response selection, audience/recipient, and XSW parser mismatch.")
    if "jwt" in categories:
        out.append("Run jwt_audit.py offline; verify alg/kid/jku/x5u/jwks_uri, exp/aud/iss/sub, and key management.")
    if "cookie" in categories or risks:
        out.append("Review cookie flags, session rotation, fixation, logout invalidation, CSRF binding, and cross-subdomain scope.")
    if "tenant" in categories:
        out.append("Use owned accounts/synthetic tenants to validate server-side tenant and object authorization.")
    return out


def analyze(path: Path, max_files: int, max_size: int) -> dict:
    root = path.resolve()
    files = list(iter_files(root, max_files, max_size))
    hits: list[Hit] = []
    risks: list[str] = []
    for item in files:
        item_hits, item_risks = scan_file(item, root if root.is_dir() else item.parent)
        hits.extend(item_hits)
        risks.extend(item_risks)
    categories = {hit.category for hit in hits}
    return {
        "artifact": str(root),
        "files_scanned": len(files),
        "summary": dict(Counter(hit.category for hit in hits).most_common()),
        "cookie_risks": dict(Counter(risks).most_common()),
        "hits": [asdict(hit) for hit in hits],
        "hypotheses": hypotheses(categories, risks),
        "limits": ["passive extraction only", "does not validate token signatures or perform auth bypass"],
    }


def print_markdown(payload: dict) -> None:
    print("# Wuyun Auth Surface Audit")
    print()
    print(f"- Artifact: `{payload['artifact']}`")
    print(f"- Files scanned: `{payload['files_scanned']}`")
    print("## Summary")
    for key, value in payload["summary"].items():
        print(f"- `{key}`: {value}")
    if not payload["summary"]:
        print("- No configured auth/session signals found.")
    print("## Cookie Risks")
    for key, value in payload["cookie_risks"].items():
        print(f"- `{key}`: {value}")
    if not payload["cookie_risks"]:
        print("- None from parsed Set-Cookie headers.")
    print("## Hits")
    for hit in payload["hits"][:160]:
        print(f"- `{hit['category']}` / `{hit['rule']}` at `{hit['file']}:{hit['line']}`: {hit['evidence']}")
    print("## Hypotheses")
    for item in payload["hypotheses"]:
        print(f"- {item}")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Passively extract auth/session surfaces.")
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
