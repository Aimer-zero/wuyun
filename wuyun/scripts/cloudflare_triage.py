#!/usr/bin/env python3
"""Passive Cloudflare/CDN/WAF response triage for Wuyun.

Reads local headers/body/HAR files only. It does not send network requests,
solve challenges, bypass WAF rules, or contact Cloudflare.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class Indicator:
    kind: str
    evidence: str
    confidence: str = "medium"


@dataclass
class Finding:
    url: str | None = None
    status: int | None = None
    classification: str = "no-cloudflare-indicators"
    confidence: str = "low"
    ray_ids: list[str] = field(default_factory=list)
    indicators: list[Indicator] = field(default_factory=list)
    safe_next_steps: list[str] = field(default_factory=list)


def read_optional(path: str | None) -> str:
    if not path:
        return ""
    return Path(path).read_text(encoding="utf-8", errors="replace")


def parse_raw_headers(raw: str) -> dict[str, list[str]]:
    headers: dict[str, list[str]] = {}
    for line in raw.splitlines():
        if not line.strip() or line.lower().startswith("http/"):
            continue
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers.setdefault(name.strip().lower(), []).append(value.strip())
    return headers


def headers_from_har(items: list[dict[str, Any]]) -> dict[str, list[str]]:
    headers: dict[str, list[str]] = {}
    for item in items:
        name = str(item.get("name", "")).strip().lower()
        if not name:
            continue
        headers.setdefault(name, []).append(str(item.get("value", "")).strip())
    return headers


def has_header(headers: dict[str, list[str]], name: str) -> bool:
    return name.lower() in headers


def header_values(headers: dict[str, list[str]], name: str) -> list[str]:
    return headers.get(name.lower(), [])


def add(indicators: list[Indicator], kind: str, evidence: str, confidence: str = "medium") -> None:
    indicators.append(Indicator(kind=kind, evidence=evidence[:240], confidence=confidence))


def classify(status: int | None, headers: dict[str, list[str]], body: str, url: str | None = None) -> Finding:
    indicators: list[Indicator] = []
    ray_ids: list[str] = []
    body_l = body.lower()

    server = ", ".join(header_values(headers, "server"))
    if "cloudflare" in server.lower():
        add(indicators, "cloudflare-cdn", f"server: {server}", "high")

    for name in ["cf-ray", "cf-cache-status", "cf-mitigated", "cf-chl-out", "cf-request-id", "cf-worker"]:
        if has_header(headers, name):
            values = header_values(headers, name)
            add(indicators, "cloudflare-header", f"{name}: {', '.join(values)}", "high")
            if name == "cf-ray":
                ray_ids.extend(values)

    if re.search(r"\berror\s+1020\b|access denied", body, re.I) and "cloudflare" in body_l:
        add(indicators, "cloudflare-waf-block", "body contains Cloudflare access denied / error 1020", "high")
    if "just a moment" in body_l and "cloudflare" in body_l:
        add(indicators, "cloudflare-challenge", "body contains Cloudflare browser challenge text", "high")
    if "turnstile" in body_l or "cf-turnstile" in body_l:
        add(indicators, "cloudflare-turnstile", "body contains Turnstile marker", "high")
    if "cf-error-code" in body_l:
        add(indicators, "cloudflare-error-page", "body contains cf-error-code marker", "high")

    mitigated = ",".join(header_values(headers, "cf-mitigated")).lower()
    cache_only = has_header(headers, "cf-cache-status") and not any(i.kind.startswith("cloudflare-waf") or "challenge" in i.kind for i in indicators)
    cf_present = any(i.kind.startswith("cloudflare") for i in indicators)

    if "challenge" in mitigated or any("challenge" in i.kind or "turnstile" in i.kind for i in indicators):
        classification = "cloudflare-challenge-or-bot-mitigation"
        confidence = "high"
    elif any(i.kind in {"cloudflare-waf-block", "cloudflare-error-page"} for i in indicators) or (status in {403, 429} and cf_present):
        classification = "cloudflare-waf-or-rate-limit-block"
        confidence = "high" if cf_present else "medium"
    elif cf_present and cache_only:
        classification = "cloudflare-cdn-cache-present"
        confidence = "medium"
    elif cf_present:
        classification = "cloudflare-present-no-clear-block"
        confidence = "medium"
    else:
        classification = "no-cloudflare-indicators"
        confidence = "low"

    steps = safe_steps(classification, ray_ids)
    return Finding(url=url, status=status, classification=classification, confidence=confidence, ray_ids=ray_ids, indicators=indicators, safe_next_steps=steps)


def safe_steps(classification: str, ray_ids: list[str]) -> list[str]:
    steps = []
    if ray_ids:
        steps.append("Use the Cloudflare Ray ID(s) to locate matching Security Events or logs with the zone owner.")
    if classification in {"cloudflare-waf-or-rate-limit-block", "cloudflare-challenge-or-bot-mitigation"}:
        steps.extend([
            "Separate WAF behavior from origin behavior; do not report origin safety based only on a WAF block.",
            "For owner-authorized testing, use a staging hostname/path or scoped skip/allow rule for tester IP/account and replay the minimal request.",
            "For production-safe reviews without owner controls, downgrade confidence and request owner-assisted replay or logs.",
            "Do not automate CAPTCHA/Turnstile solving, proxy rotation, or generic WAF evasion on third-party systems.",
        ])
    elif classification.startswith("cloudflare-cdn") or classification == "cloudflare-present-no-clear-block":
        steps.extend([
            "Continue normal low-impact Web/API mapping; record Cloudflare headers because caching/rules may affect reproducibility.",
            "If behavior differs by cache status, test with owner-approved cache-bypass or staging controls.",
        ])
    else:
        steps.append("No Cloudflare indicator was found in provided artifacts; continue application-layer analysis and look for origin/app errors.")
    return steps


def analyze_har(path: str) -> list[Finding]:
    data = json.loads(Path(path).read_text(encoding="utf-8", errors="replace"))
    entries = data.get("log", {}).get("entries", [])
    findings: list[Finding] = []
    for entry in entries:
        req = entry.get("request", {})
        resp = entry.get("response", {})
        headers = headers_from_har(resp.get("headers", []))
        content = resp.get("content", {}) or {}
        body = content.get("text", "") or ""
        findings.append(classify(resp.get("status"), headers, body, req.get("url")))
    return findings


def print_markdown(findings: list[Finding]) -> None:
    print("# Wuyun Cloudflare WAF Triage")
    print()
    for idx, finding in enumerate(findings, start=1):
        label = finding.url or f"response-{idx}"
        print(f"## {idx}. {label}")
        print(f"- Status: `{finding.status}`")
        print(f"- Classification: `{finding.classification}`")
        print(f"- Confidence: `{finding.confidence}`")
        if finding.ray_ids:
            print("- Ray IDs: " + ", ".join(f"`{x}`" for x in finding.ray_ids))
        print("\n### Indicators")
        if finding.indicators:
            for item in finding.indicators:
                print(f"- `{item.kind}` ({item.confidence}): {item.evidence}")
        else:
            print("- None detected in provided artifacts.")
        print("\n### Safe Next Steps")
        for step in finding.safe_next_steps:
            print(f"- {step}")
        print()


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Passive Cloudflare/CDN/WAF triage from local response artifacts.")
    parser.add_argument("--headers", help="file containing raw response headers")
    parser.add_argument("--body", help="file containing response body")
    parser.add_argument("--har", help="HAR file to analyze")
    parser.add_argument("--status", type=int, help="HTTP status for --headers/--body input")
    parser.add_argument("--url", help="URL label for --headers/--body input")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of Markdown")
    args = parser.parse_args(argv)

    if args.har:
        findings = analyze_har(args.har)
    else:
        if not args.headers and not args.body:
            parser.error("provide --har or at least one of --headers/--body")
        headers = parse_raw_headers(read_optional(args.headers))
        body = read_optional(args.body)
        findings = [classify(args.status, headers, body, args.url)]

    if args.json:
        print(json.dumps([asdict(f) for f in findings], ensure_ascii=False, indent=2))
    else:
        print_markdown(findings)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
