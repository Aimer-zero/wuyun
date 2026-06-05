#!/usr/bin/env python3
"""Detect cloud credential-shaped evidence in text without validating it online.

The script is intentionally offline and redaction-first. It never contacts cloud
APIs, never persists raw credential values, and defaults to Markdown output that
is safe to paste into a vulnerability report.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

SENSITIVE_FIELDS = {
    "accesskeyid",
    "accesskeysecret",
    "secretaccesskey",
    "securitytoken",
    "sessiontoken",
    "tmpsecretid",
    "tmpsecretkey",
    "token",
    "access_token",
    "refresh_token",
}

FIELD_RE = re.compile(
    r"(?i)(?P<key>AccessKeyId|AccessKeySecret|SecurityToken|SecretAccessKey|SessionToken|TmpSecretId|TmpSecretKey|Token|access_token|refresh_token|expires_in|expires_on|Expiration|ExpiredTime|Code|role|RoleName|InstanceId)"
    r"\s*[\"']?\s*[:=]\s*[\"']?(?P<value>[^\"'\s,}]{1,300})"
)

INDICATOR_PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    ("aws", "aws-temporary-access-key", re.compile(r"\bASIA[0-9A-Z]{16}\b")),
    ("aws", "aws-long-term-access-key-shape", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("aliyun", "aliyun-temporary-access-key-shape", re.compile(r"\bSTS\.[A-Za-z0-9._-]{8,}\b")),
    ("tencent", "tencent-secret-id-shape", re.compile(r"\bAKID[A-Za-z0-9]{13,}\b")),
    ("gcp", "gcp-oauth-access-token-shape", re.compile(r"\bya29\.[A-Za-z0-9._-]{20,}\b")),
)

METADATA_HINTS: tuple[tuple[str, str], ...] = (
    ("aliyun", "100.100.100.200"),
    ("aws", "169.254.169.254"),
    ("tencent", "metadata.tencentyun.com"),
    ("gcp", "metadata.google.internal"),
    ("azure", "metadata/instance"),
)


@dataclass
class Evidence:
    provider: str
    kind: str
    field: str
    value_redacted: str
    confidence: str
    source: str


def redact(value: str, sensitive: bool = True) -> str:
    value = value.strip().strip('"\'')
    if not value:
        return "<empty>"
    if len(value) <= 8:
        return f"<redacted len={len(value)}>" if sensitive else value
    if sensitive:
        return f"{value[:4]}…{value[-4:]} (len={len(value)})"
    if len(value) > 64:
        return f"{value[:32]}…{value[-8:]} (len={len(value)})"
    return value


def provider_from_fields(fields: dict[str, list[str]]) -> tuple[str, str]:
    lower = {k.lower() for k in fields}
    vals = " ".join(v for values in fields.values() for v in values)
    if {"tmpsecretid", "tmpsecretkey"} & lower:
        return "tencent", "high" if "token" in lower else "medium"
    if "secretaccesskey" in lower or re.search(r"\bASIA[0-9A-Z]{16}\b", vals):
        return "aws", "high" if "token" in lower else "medium"
    if "accesskeysecret" in lower or "securitytoken" in lower or "AccessKeyId" in fields and "SecurityToken" in fields:
        return "aliyun", "high" if {"accesskeyid", "accesskeysecret", "securitytoken"}.issubset(lower) else "medium"
    if "access_token" in lower:
        if "expires_on" in lower:
            return "azure", "medium"
        return "gcp-or-azure", "medium"
    return "unknown", "low"


def scan_text(text: str, source: str) -> list[Evidence]:
    evidence: list[Evidence] = []
    fields: dict[str, list[str]] = {}
    for match in FIELD_RE.finditer(text):
        key = match.group("key")
        value = match.group("value")
        fields.setdefault(key, []).append(value)

    provider, base_confidence = provider_from_fields(fields)
    for key, values in sorted(fields.items()):
        sensitive = key.lower() in SENSITIVE_FIELDS or "secret" in key.lower() or "token" in key.lower()
        for value in values[:10]:
            evidence.append(Evidence(provider, "field", key, redact(value, sensitive=sensitive), base_confidence, source))

    for pattern_provider, kind, regex in INDICATOR_PATTERNS:
        for match in regex.finditer(text):
            evidence.append(Evidence(pattern_provider, kind, "pattern", redact(match.group(0)), "medium", source))

    lowered = text.lower()
    for hint_provider, hint in METADATA_HINTS:
        if hint.lower() in lowered:
            evidence.append(Evidence(hint_provider, "metadata-endpoint-indicator", "endpoint", hint, "low", source))

    return dedupe(evidence)


def dedupe(items: Iterable[Evidence]) -> list[Evidence]:
    seen: set[tuple[str, str, str, str, str]] = set()
    out: list[Evidence] = []
    for item in items:
        key = (item.provider, item.kind, item.field, item.value_redacted, item.source)
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out


def read_inputs(paths: list[str]) -> list[tuple[str, str]]:
    if not paths:
        return [("<stdin>", sys.stdin.read())]
    items: list[tuple[str, str]] = []
    for raw in paths:
        path = Path(raw)
        try:
            items.append((str(path), path.read_text(encoding="utf-8", errors="replace")))
        except OSError as exc:
            print(f"warning: could not read {path}: {exc}", file=sys.stderr)
    return items


def confidence_summary(items: list[Evidence]) -> str:
    if any(i.confidence == "high" for i in items):
        return "high"
    if any(i.confidence == "medium" for i in items):
        return "medium"
    if items:
        return "low"
    return "none"


def print_markdown(items: list[Evidence]) -> None:
    print("# Cloud Credential Evidence Triage")
    print()
    print(f"- Findings: `{len(items)}`")
    print(f"- Overall confidence: `{confidence_summary(items)}`")
    print("- Online validation: `not performed`")
    print("- Redaction: raw credential-like values were not printed")
    print()
    if not items:
        print("No configured cloud credential indicators were detected. This is not proof of absence.")
        return
    print("| Provider | Kind | Field | Redacted evidence | Confidence | Source |")
    print("|---|---|---|---|---|---|")
    for item in items:
        print(
            f"| {item.provider} | {item.kind} | `{item.field}` | `{item.value_redacted}` | {item.confidence} | `{item.source}` |"
        )
    print()
    print("## Safe Next Step")
    print("- Production/bounty: rotate exposed credentials, preserve redacted evidence, and infer impact offline from role/policy context.")
    print("- CTF/lab: use only the minimum cloud action needed to retrieve the intended artifact.")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Offline redacted cloud token evidence detector.")
    parser.add_argument("paths", nargs="*", help="text/JSON evidence files; stdin is used when omitted")
    parser.add_argument("--json", action="store_true", help="emit redacted JSON")
    args = parser.parse_args(argv)

    findings: list[Evidence] = []
    for source, text in read_inputs(args.paths):
        findings.extend(scan_text(text, source))
    findings = dedupe(findings)

    if args.json:
        print(json.dumps({"findings": [asdict(item) for item in findings], "online_validation": False}, ensure_ascii=False, indent=2))
    else:
        print_markdown(findings)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
