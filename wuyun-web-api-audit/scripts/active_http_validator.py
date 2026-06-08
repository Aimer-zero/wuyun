#!/usr/bin/env python3
"""Authorized low-impact HTTP validation runner for Wuyun Web/API audits.

Default mode is dry-run. The runner sends requests only when both
--authorize-active-testing and --scope-host are provided. It changes one
parameter at a time, rate-limits requests, and records response differences.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


SENSITIVE_HEADER = re.compile(r"(?i)authorization|cookie|x-api-key|token|secret|password")
ERROR_PATTERNS = {
    "sql-error": re.compile(r"(?i)(sql syntax|mysql|postgres|sqlite|ora-\d+|odbc|jdbc|unterminated|syntax error)"),
    "stack-trace": re.compile(r"(?i)(traceback|stack trace|exception|at [\w.$]+\(.*:\d+\))"),
    "template-error": re.compile(r"(?i)(template error|jinja|twig|freemarker|velocity|handlebars)"),
}
PROFILES = {
    "marker": ["wuyun-marker", "wuyun-marker-2"],
    "syntax-smoke": ["wuyun'\"", "wuyun\\", "wuyun<>{}"],
    "authz-smoke": ["1", "2", "999999"],
}


@dataclass
class ProbeResult:
    label: str
    value: str
    status: int | None
    elapsed_ms: int
    body_len: int
    body_sha256_12: str
    content_type: str
    error: str | None
    markers: list[str]


def parse_headers(items: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for item in items:
        if ":" not in item:
            raise ValueError(f"header must be 'Name: value': {item}")
        key, value = item.split(":", 1)
        headers[key.strip()] = value.strip()
    return headers


def compact_headers(headers: dict[str, str]) -> dict[str, str]:
    out = {}
    for key, value in headers.items():
        out[key] = "<compact-sensitive-value>" if SENSITIVE_HEADER.search(key) else value
    return out


def load_values(args: argparse.Namespace) -> list[str]:
    values: list[str] = []
    if args.profile:
        values.extend(PROFILES[args.profile])
    if args.values:
        for chunk in args.values:
            values.extend([item for item in chunk.split(",") if item])
    if args.values_file:
        values.extend([
            line.strip()
            for line in Path(args.values_file).read_text(encoding="utf-8", errors="replace").splitlines()
            if line.strip() and not line.strip().startswith("#")
        ])
    return values


def mutate_url(url: str, param: str | None, value: str | None) -> str:
    if not param or value is None:
        return url
    parsed = urllib.parse.urlparse(url)
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    query[param] = [value]
    new_query = urllib.parse.urlencode(query, doseq=True)
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))


def mutate_body(body: str | None, json_field: str | None, value: str | None) -> bytes | None:
    if body is None:
        return None
    if not json_field or value is None:
        return body.encode("utf-8")
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        return body.encode("utf-8")
    if isinstance(payload, dict):
        payload[json_field] = value
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def body_markers(body: bytes) -> list[str]:
    text = body[:200_000].decode("utf-8", errors="replace")
    return [name for name, pattern in ERROR_PATTERNS.items() if pattern.search(text)]


def summarize_body(body: bytes) -> tuple[int, str, list[str]]:
    return len(body), hashlib.sha256(body).hexdigest()[:12], body_markers(body)


def send_request(method: str, url: str, headers: dict[str, str], body: bytes | None, timeout: float) -> ProbeResult:
    request = urllib.request.Request(url, data=body, headers=headers, method=method.upper())
    start = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            response_body = response.read(500_000)
            elapsed = int((time.monotonic() - start) * 1000)
            body_len, body_hash, markers = summarize_body(response_body)
            return ProbeResult(
                label="",
                value="",
                status=response.status,
                elapsed_ms=elapsed,
                body_len=body_len,
                body_sha256_12=body_hash,
                content_type=response.headers.get("content-type", ""),
                error=None,
                markers=markers,
            )
    except urllib.error.HTTPError as exc:
        response_body = exc.read(500_000)
        elapsed = int((time.monotonic() - start) * 1000)
        body_len, body_hash, markers = summarize_body(response_body)
        return ProbeResult(
            label="",
            value="",
            status=exc.code,
            elapsed_ms=elapsed,
            body_len=body_len,
            body_sha256_12=body_hash,
            content_type=exc.headers.get("content-type", "") if exc.headers else "",
            error=None,
            markers=markers,
        )
    except Exception as exc:  # noqa: BLE001 - summarize network failure without crashing batch
        elapsed = int((time.monotonic() - start) * 1000)
        return ProbeResult(
            label="",
            value="",
            status=None,
            elapsed_ms=elapsed,
            body_len=0,
            body_sha256_12="",
            content_type="",
            error=f"{type(exc).__name__}: {exc}",
            markers=[],
        )


def compare(base: ProbeResult, probe: ProbeResult) -> dict[str, Any]:
    return {
        "status_changed": base.status != probe.status,
        "length_delta": probe.body_len - base.body_len,
        "hash_changed": base.body_sha256_12 != probe.body_sha256_12,
        "new_markers": sorted(set(probe.markers) - set(base.markers)),
    }


def enforce_scope(url: str, scope_hosts: list[str]) -> None:
    host = urllib.parse.urlparse(url).hostname or ""
    allowed = {item.lower() for item in scope_hosts}
    if host.lower() not in allowed:
        raise ValueError(f"target host `{host}` is not in --scope-host allowlist")


def build_plan(args: argparse.Namespace, values: list[str], headers: dict[str, str]) -> dict[str, Any]:
    return {
        "target": args.url,
        "method": args.method.upper(),
        "scope_hosts": args.scope_host,
        "query_param": args.param,
        "json_field": args.json_field,
        "requests_planned": 1 + len(values),
        "rate_limit_seconds": args.delay,
        "headers": compact_headers(headers),
        "values": values,
        "authorized": args.authorize_active_testing,
        "limits": [
            "single endpoint only",
            "one variable changed at a time",
            "response body capped at 500KB",
            "no data extraction or high-volume scanning",
        ],
    }


def execute(args: argparse.Namespace, values: list[str], headers: dict[str, str]) -> dict[str, Any]:
    enforce_scope(args.url, args.scope_host)
    baseline_url = mutate_url(args.url, args.param, args.baseline_value) if args.baseline_value is not None else args.url
    baseline_body = mutate_body(args.body, args.json_field, args.baseline_value)
    baseline = send_request(args.method, baseline_url, headers, baseline_body, args.timeout)
    baseline.label = "baseline"
    baseline.value = args.baseline_value or "<original>"
    results = [baseline]
    comparisons = []

    for index, value in enumerate(values[: args.max_requests], start=1):
        time.sleep(args.delay)
        url = mutate_url(args.url, args.param, value)
        body = mutate_body(args.body, args.json_field, value)
        result = send_request(args.method, url, headers, body, args.timeout)
        result.label = f"probe-{index}"
        result.value = value
        results.append(result)
        comparisons.append({"label": result.label, "value": value, **compare(baseline, result)})

    return {
        "plan": build_plan(args, values[: args.max_requests], headers),
        "results": [asdict(item) for item in results],
        "comparisons": comparisons,
        "status": "executed",
    }


def print_markdown(payload: dict[str, Any]) -> None:
    plan = payload["plan"]
    print("# Wuyun Active HTTP Validation")
    print()
    print(f"- Status: `{payload['status']}`")
    print(f"- Target: `{plan['method']} {plan['target']}`")
    print(f"- Scope hosts: `{', '.join(plan['scope_hosts']) or '<missing>'}`")
    print(f"- Query param: `{plan['query_param'] or ''}`")
    print(f"- JSON field: `{plan['json_field'] or ''}`")
    print(f"- Requests planned: `{plan['requests_planned']}`")
    print()
    if payload["status"] == "dry-run":
        print("## Dry Run")
        print("- Add `--authorize-active-testing` and matching `--scope-host` to send requests.")
        print("- Review values, target, and authorization before execution.")
    else:
        print("## Results")
        for row in payload["results"]:
            markers = ", ".join(row["markers"]) if row["markers"] else "none"
            print(f"- `{row['label']}` value `{row['value']}` -> status `{row['status']}` len `{row['body_len']}` hash `{row['body_sha256_12']}` markers: {markers} error: `{row['error'] or ''}`")
        print()
        print("## Differences")
        for row in payload["comparisons"]:
            markers = ", ".join(row["new_markers"]) if row["new_markers"] else "none"
            print(f"- `{row['label']}` value `{row['value']}`: status_changed=`{row['status_changed']}` length_delta=`{row['length_delta']}` hash_changed=`{row['hash_changed']}` new_markers={markers}")
    print()
    print("## Limits")
    for item in plan["limits"]:
        print(f"- {item}")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Authorized low-impact HTTP parameter validation runner.")
    parser.add_argument("--url", required=True, help="single in-scope endpoint URL")
    parser.add_argument("--method", default="GET", help="HTTP method")
    parser.add_argument("--header", action="append", default=[], help="request header as 'Name: value'")
    parser.add_argument("--body", help="request body; use with JSON field mutation when applicable")
    parser.add_argument("--param", help="query parameter to mutate")
    parser.add_argument("--json-field", help="top-level JSON field to mutate")
    parser.add_argument("--baseline-value", help="optional baseline value for param/json-field")
    parser.add_argument("--profile", choices=sorted(PROFILES), help="built-in low-impact value profile")
    parser.add_argument("--values", action="append", help="comma-separated explicit values")
    parser.add_argument("--values-file", help="newline-separated explicit values")
    parser.add_argument("--scope-host", action="append", default=[], help="authorized host allowlist; required for execution")
    parser.add_argument("--authorize-active-testing", action="store_true", help="confirm written authorization for this exact target/scope")
    parser.add_argument("--delay", type=float, default=1.0, help="seconds between probes")
    parser.add_argument("--timeout", type=float, default=10.0, help="request timeout seconds")
    parser.add_argument("--max-requests", type=int, default=10, help="maximum probe requests, excluding baseline")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    args = parser.parse_args(argv)

    if not args.param and not args.json_field:
        print("error: provide --param or --json-field to mutate one variable", file=sys.stderr)
        return 2
    try:
        headers = parse_headers(args.header)
        values = load_values(args)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if not values:
        print("error: provide --profile, --values, or --values-file", file=sys.stderr)
        return 2
    if args.delay < 0.2:
        print("error: --delay must be >= 0.2 seconds", file=sys.stderr)
        return 2
    if args.max_requests > 50:
        print("error: --max-requests must be <= 50", file=sys.stderr)
        return 2

    if not args.authorize_active_testing:
        payload = {"plan": build_plan(args, values[: args.max_requests], headers), "results": [], "comparisons": [], "status": "dry-run"}
    else:
        if not args.scope_host:
            print("error: --scope-host is required with --authorize-active-testing", file=sys.stderr)
            return 2
        try:
            payload = execute(args, values, headers)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print_markdown(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
