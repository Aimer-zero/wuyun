#!/usr/bin/env python3
"""Passive HAR analyzer for Wuyun browser/runtime workflows.

Reads local HAR JSON only. It does not replay requests or contact targets.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import urlparse, urlunparse


SENSITIVE_HEADERS = {"authorization", "cookie", "set-cookie", "x-csrf-token", "x-xsrf-token"}


@dataclass
class RequestSummary:
    method: str
    url: str
    host: str
    path: str
    status: int
    mime_type: str
    risk_signals: list[str]


def header_map(headers: list[dict]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = defaultdict(list)
    for header in headers or []:
        name = str(header.get("name", "")).lower()
        value = str(header.get("value", ""))
        if name:
            out[name].append(value)
    return dict(out)


def compact_header(name: str, values: list[str], complete: bool) -> str:
    joined = "; ".join(values)
    if complete or name.lower() not in SENSITIVE_HEADERS:
        return joined[:300]
    return "<compact-sensitive-value>"


def compact_url(url: str, complete: bool) -> str:
    if complete:
        return url[:500]
    parsed = urlparse(url)
    query = "<query-redacted>" if parsed.query else ""
    fragment = "<fragment-redacted>" if parsed.fragment else ""
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, fragment))[:500]


def classify_signals(req_headers: dict[str, list[str]], resp_headers: dict[str, list[str]], status: int, body_hint: str) -> list[str]:
    signals: list[str] = []
    merged = {**req_headers, **resp_headers}
    server = " ".join(resp_headers.get("server", [])).lower()
    body = body_hint.lower()
    header_names = set(merged)
    cookie_values = " ".join(resp_headers.get("set-cookie", []) + req_headers.get("cookie", [])).lower()

    if "cf-ray" in header_names or "cloudflare" in server or "__cf_bm" in cookie_values or "cf_clearance" in cookie_values:
        signals.append("cloudflare")
    if any(name.startswith("x-akamai") for name in header_names) or "akamai" in server or "_abck" in cookie_values:
        signals.append("akamai")
    if "x-iinfo" in header_names or "incap_ses" in cookie_values or "visid_incap" in cookie_values:
        signals.append("imperva/incapsula")
    if "x-sucuri-id" in header_names or "sucuri" in server:
        signals.append("sucuri")
    if "x-amzn-trace-id" in header_names or "x-amzn-waf" in header_names:
        signals.append("aws-edge-or-waf")
    if status in {401, 403, 429, 503}:
        signals.append(f"status-{status}")
    if "retry-after" in header_names or any(name.startswith("x-ratelimit") for name in header_names):
        signals.append("rate-limit")
    if re.search(r"captcha|turnstile|challenge|bot|verify you are human|access denied", body):
        signals.append("challenge-or-bot-defense-body")
    if "authorization" in req_headers:
        signals.append("auth-header-present")
    if "cookie" in req_headers:
        signals.append("cookie-present")
    return sorted(set(signals))


def extract_entries(payload: dict) -> list[dict]:
    if "log" in payload and isinstance(payload["log"], dict):
        entries = payload["log"].get("entries", [])
        return entries if isinstance(entries, list) else []
    if "entries" in payload and isinstance(payload["entries"], list):
        return payload["entries"]
    return []


def summarize_entry(entry: dict) -> RequestSummary:
    request = entry.get("request", {}) or {}
    response = entry.get("response", {}) or {}
    url = str(request.get("url", ""))
    parsed = urlparse(url)
    status = int(response.get("status") or 0)
    req_headers = header_map(request.get("headers", []))
    resp_headers = header_map(response.get("headers", []))
    content = response.get("content", {}) or {}
    body_hint = str(content.get("text", ""))[:4000]
    return RequestSummary(
        method=str(request.get("method", "GET")),
        url=url,
        host=parsed.netloc,
        path=parsed.path or "/",
        status=status,
        mime_type=str(content.get("mimeType", "")),
        risk_signals=classify_signals(req_headers, resp_headers, status, body_hint),
    )


def analyze(path: Path, complete: bool) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    entries = extract_entries(payload)
    summaries = [summarize_entry(entry) for entry in entries]
    host_counts = Counter(item.host for item in summaries if item.host)
    status_counts = Counter(str(item.status) for item in summaries)
    method_counts = Counter(item.method for item in summaries)
    signal_counts = Counter(signal for item in summaries for signal in item.risk_signals)

    endpoints: dict[tuple[str, str, str], RequestSummary] = {}
    for item in summaries:
        endpoints.setdefault((item.method, item.host, item.path), item)

    trace_headers: list[dict] = []
    for entry in entries:
        request = entry.get("request", {}) or {}
        response = entry.get("response", {}) or {}
        url = str(request.get("url", ""))
        resp_headers = header_map(response.get("headers", []))
        req_headers = header_map(request.get("headers", []))
        interesting = {}
        for name in [
            "cf-ray", "x-request-id", "x-correlation-id", "x-amzn-trace-id",
            "x-cache", "cf-cache-status", "server", "retry-after",
        ]:
            values = resp_headers.get(name) or req_headers.get(name)
            if values:
                interesting[name] = compact_header(name, values, complete)
        if interesting:
            trace_headers.append({"url": compact_url(url, complete), "headers": interesting})

    return {
        "file": str(path),
        "entries": len(entries),
        "hosts": dict(host_counts.most_common(30)),
        "methods": dict(method_counts),
        "statuses": dict(status_counts),
        "signals": dict(signal_counts.most_common()),
        "endpoints": [asdict(item) for item in endpoints.values()],
        "trace_headers": trace_headers[:200],
        "limits": [
            "HAR analysis is passive and does not prove server-side vulnerability",
            "blocked/challenged requests should be classified before further replay",
            "sensitive request headers are compacted unless --complete-evidence is used",
        ],
    }


def print_markdown(payload: dict) -> None:
    print("# Wuyun HAR Analysis")
    print()
    print(f"- File: `{payload['file']}`")
    print(f"- Entries: `{payload['entries']}`")
    print()
    print("## Hosts")
    for host, count in payload["hosts"].items():
        print(f"- `{host}`: {count}")
    print()
    print("## Methods / Statuses")
    print("- Methods: " + (", ".join(f"`{k}`={v}" for k, v in payload["methods"].items()) or "none"))
    print("- Statuses: " + (", ".join(f"`{k}`={v}" for k, v in payload["statuses"].items()) or "none"))
    print()
    print("## Protection / Runtime Signals")
    if payload["signals"]:
        for signal, count in payload["signals"].items():
            print(f"- `{signal}`: {count}")
    else:
        print("- No configured protection/runtime signals found.")
    print()
    print("## Endpoint Inventory")
    for item in payload["endpoints"][:120]:
        signals = ", ".join(item["risk_signals"]) if item["risk_signals"] else "none"
        print(f"- `{item['method']}` `{item['host']}{item['path']}` -> `{item['status']}` `{item['mime_type']}` signals: {signals}")
    if len(payload["endpoints"]) > 120:
        print(f"- ... {len(payload['endpoints']) - 120} additional endpoints omitted; use `--json` for full output.")
    print()
    print("## Trace Headers")
    for item in payload["trace_headers"][:50]:
        header_text = ", ".join(f"`{k}`=`{v}`" for k, v in item["headers"].items())
        print(f"- `{item['url']}`: {header_text}")
    if not payload["trace_headers"]:
        print("- No configured trace headers found.")
    print()
    print("## Limits")
    for item in payload["limits"]:
        print(f"- {item}")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Passively analyze a local HAR file.")
    parser.add_argument("path", help="HAR JSON file")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    parser.add_argument("--complete-evidence", action="store_true", help="do not compact sensitive-looking headers")
    args = parser.parse_args(argv)

    path = Path(args.path).resolve()
    if not path.exists():
        print(f"error: HAR file does not exist: {path}", file=sys.stderr)
        return 2
    try:
        payload = analyze(path, complete=args.complete_evidence)
    except json.JSONDecodeError as exc:
        print(f"error: invalid JSON/HAR: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print_markdown(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
