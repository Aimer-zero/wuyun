#!/usr/bin/env python3
"""Authorized low-impact HTTP validation runner for Wuyun Web/API audits.

Default mode is dry-run. The runner sends requests only when both
--authorize-active-testing and --scope-host are provided. It changes one
parameter at a time, rate-limits requests, and records response differences.
"""
from __future__ import annotations

import argparse
import base64
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


@dataclass
class HttpSpec:
    method: str
    url: str
    headers: dict[str, str]
    body: str | None


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


def parse_raw_request(path: str, base_url: str | None) -> HttpSpec:
    text = Path(path).read_text(encoding="utf-8", errors="replace").replace("\r\n", "\n")
    head, sep, body = text.partition("\n\n")
    lines = [line for line in head.splitlines() if line.strip()]
    if not lines:
        raise ValueError("request file is empty")
    start = lines[0].split()
    if len(start) < 2:
        raise ValueError("request file must start with an HTTP request line")
    method, target = start[0].upper(), start[1]
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip()] = value.strip()
    if target.startswith("http://") or target.startswith("https://"):
        url = target
    else:
        host = headers.get("Host") or headers.get("host")
        if base_url:
            url = urllib.parse.urljoin(base_url.rstrip("/") + "/", target.lstrip("/"))
        elif host:
            scheme = "https" if headers.get("X-Forwarded-Proto", "").lower() == "https" else "http"
            url = f"{scheme}://{host}{target if target.startswith('/') else '/' + target}"
        else:
            raise ValueError("relative request target requires --base-url or Host header")
    return HttpSpec(method=method, url=url, headers=headers, body=body if sep else None)


def mutate_url(url: str, param: str | None, value: str | None) -> str:
    if not param or value is None:
        return url
    parsed = urllib.parse.urlparse(url)
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    query[param] = [value]
    new_query = urllib.parse.urlencode(query, doseq=True)
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))


def mutate_path_placeholder(url: str, placeholder: str | None, value: str | None) -> str:
    if not placeholder or value is None:
        return url
    encoded = urllib.parse.quote(value, safe="")
    return url.replace(placeholder, encoded)


def set_json_path(payload: Any, path: str, value: str) -> Any:
    if not path:
        return payload
    current = payload
    parts = [part for part in path.split(".") if part]
    for part in parts[:-1]:
        if isinstance(current, dict):
            current = current.setdefault(part, {})
        else:
            return payload
    if parts and isinstance(current, dict):
        current[parts[-1]] = value
    return payload


def mutate_form_body(body: str, form_field: str | None, value: str | None) -> bytes:
    if not form_field or value is None:
        return body.encode("utf-8")
    pairs = urllib.parse.parse_qsl(body, keep_blank_values=True)
    seen = False
    updated = []
    for key, existing in pairs:
        if key == form_field:
            updated.append((key, value))
            seen = True
        else:
            updated.append((key, existing))
    if not seen:
        updated.append((form_field, value))
    return urllib.parse.urlencode(updated, doseq=True).encode("utf-8")


def mutate_body(body: str | None, json_field: str | None, json_path: str | None, form_field: str | None, value: str | None) -> bytes | None:
    if body is None:
        return None
    if value is None:
        return body.encode("utf-8")
    if form_field:
        return mutate_form_body(body, form_field, value)
    if not json_field and not json_path:
        return body.encode("utf-8")
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        return body.encode("utf-8")
    if isinstance(payload, dict):
        if json_path:
            payload = set_json_path(payload, json_path, value)
        elif json_field:
            payload[json_field] = value
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def mutate_headers(headers: dict[str, str], header_name: str | None, value: str | None) -> dict[str, str]:
    out = dict(headers)
    if header_name and value is not None:
        out[header_name] = value
    return out


def body_excerpt(body: bytes, complete: bool) -> str:
    if not complete:
        return ""
    raw = body[:4096]
    try:
        text = raw.decode("utf-8")
        text = re.sub(
            r"(?i)(token|secret|password|credential|access[_-]?key|session|cookie)([\"'\s:=]+)[A-Za-z0-9_./+=:-]{8,}",
            r"\1\2<compact-sensitive-value>",
            text,
        )
        return text
    except UnicodeDecodeError:
        return base64.b64encode(raw).decode("ascii")


def body_markers(body: bytes) -> list[str]:
    text = body[:200_000].decode("utf-8", errors="replace")
    return [name for name, pattern in ERROR_PATTERNS.items() if pattern.search(text)]


def summarize_body(body: bytes, complete: bool = False) -> tuple[int, str, list[str], str]:
    return len(body), hashlib.sha256(body).hexdigest()[:12], body_markers(body), body_excerpt(body, complete)


def send_request(method: str, url: str, headers: dict[str, str], body: bytes | None, timeout: float, complete: bool) -> tuple[ProbeResult, str]:
    request = urllib.request.Request(url, data=body, headers=headers, method=method.upper())
    start = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            response_body = response.read(500_000)
            elapsed = int((time.monotonic() - start) * 1000)
            body_len, body_hash, markers, excerpt = summarize_body(response_body, complete=complete)
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
            ), excerpt
    except urllib.error.HTTPError as exc:
        response_body = exc.read(500_000)
        elapsed = int((time.monotonic() - start) * 1000)
        body_len, body_hash, markers, excerpt = summarize_body(response_body, complete=complete)
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
        ), excerpt
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
        ), ""


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


def build_spec(args: argparse.Namespace, cli_headers: dict[str, str]) -> HttpSpec:
    if args.request_file:
        spec = parse_raw_request(args.request_file, args.base_url)
        merged_headers = {**spec.headers, **cli_headers}
        return HttpSpec(
            method=args.method.upper() if args.method else spec.method,
            url=args.url or spec.url,
            headers=merged_headers,
            body=args.body if args.body is not None else spec.body,
        )
    if not args.url:
        raise ValueError("provide --url or --request-file")
    return HttpSpec(
        method=(args.method or "GET").upper(),
        url=args.url,
        headers=cli_headers,
        body=args.body,
    )


def mutated_request(spec: HttpSpec, args: argparse.Namespace, value: str | None) -> tuple[str, dict[str, str], bytes | None]:
    url = mutate_path_placeholder(spec.url, args.path_placeholder, value)
    url = mutate_url(url, args.param, value)
    headers = mutate_headers(spec.headers, args.header_name, value)
    body = mutate_body(spec.body, args.json_field, args.json_path, args.form_field, value)
    return url, headers, body


def build_plan(args: argparse.Namespace, values: list[str], headers: dict[str, str]) -> dict[str, Any]:
    spec = build_spec(args, headers)
    return {
        "target": spec.url,
        "method": spec.method,
        "scope_hosts": args.scope_host,
        "query_param": args.param,
        "json_field": args.json_field,
        "json_path": args.json_path,
        "form_field": args.form_field,
        "header_name": args.header_name,
        "path_placeholder": args.path_placeholder,
        "request_file": args.request_file,
        "requests_planned": 1 + len(values),
        "rate_limit_seconds": args.delay,
        "headers": compact_headers(spec.headers),
        "body_present": spec.body is not None,
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
    spec = build_spec(args, headers)
    enforce_scope(spec.url, args.scope_host)
    baseline_url, baseline_headers, baseline_body = mutated_request(spec, args, args.baseline_value)
    baseline = send_request(spec.method, baseline_url, baseline_headers, baseline_body, args.timeout, args.complete_evidence)
    baseline, baseline_excerpt = baseline
    baseline.label = "baseline"
    baseline.value = args.baseline_value or "<original>"
    results = [baseline]
    comparisons = []
    response_excerpts = {"baseline": baseline_excerpt} if baseline_excerpt else {}

    for index, value in enumerate(values[: args.max_requests], start=1):
        time.sleep(args.delay)
        url, probe_headers, body = mutated_request(spec, args, value)
        enforce_scope(url, args.scope_host)
        result, excerpt = send_request(spec.method, url, probe_headers, body, args.timeout, args.complete_evidence)
        result.label = f"probe-{index}"
        result.value = value
        results.append(result)
        comparisons.append({"label": result.label, "value": value, **compare(baseline, result)})
        if excerpt:
            response_excerpts[result.label] = excerpt

    return {
        "plan": build_plan(args, values[: args.max_requests], headers),
        "results": [asdict(item) for item in results],
        "comparisons": comparisons,
        "response_excerpts": response_excerpts,
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
    print(f"- JSON path: `{plan['json_path'] or ''}`")
    print(f"- Form field: `{plan['form_field'] or ''}`")
    print(f"- Header name: `{plan['header_name'] or ''}`")
    print(f"- Path placeholder: `{plan['path_placeholder'] or ''}`")
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
        if payload.get("response_excerpts"):
            print()
            print("## Response Excerpts")
            for label, excerpt in payload["response_excerpts"].items():
                print(f"### {label}")
                print("```text")
                print(excerpt)
                print("```")
    print()
    print("## Limits")
    for item in plan["limits"]:
        print(f"- {item}")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Authorized low-impact HTTP parameter validation runner.")
    parser.add_argument("--url", help="single in-scope endpoint URL")
    parser.add_argument("--request-file", help="raw HTTP request file; CLI flags may override method/url/body/headers")
    parser.add_argument("--base-url", help="base URL for relative request-file targets")
    parser.add_argument("--method", help="HTTP method")
    parser.add_argument("--header", action="append", default=[], help="request header as 'Name: value'")
    parser.add_argument("--header-name", help="header name to mutate")
    parser.add_argument("--body", help="request body; use with JSON field mutation when applicable")
    parser.add_argument("--path-placeholder", help="literal path placeholder to replace with each value, e.g. {id}")
    parser.add_argument("--param", help="query parameter to mutate")
    parser.add_argument("--json-field", help="top-level JSON field to mutate")
    parser.add_argument("--json-path", help="dot-separated JSON path to mutate, e.g. user.id")
    parser.add_argument("--form-field", help="application/x-www-form-urlencoded field to mutate")
    parser.add_argument("--baseline-value", help="optional baseline value for param/json-field")
    parser.add_argument("--profile", choices=sorted(PROFILES), help="built-in low-impact value profile")
    parser.add_argument("--values", action="append", help="comma-separated explicit values")
    parser.add_argument("--values-file", help="newline-separated explicit values")
    parser.add_argument("--scope-host", action="append", default=[], help="authorized host allowlist; required for execution")
    parser.add_argument("--authorize-active-testing", action="store_true", help="confirm written authorization for this exact target/scope")
    parser.add_argument("--delay", type=float, default=1.0, help="seconds between probes")
    parser.add_argument("--timeout", type=float, default=10.0, help="request timeout seconds")
    parser.add_argument("--max-requests", type=int, default=10, help="maximum probe requests, excluding baseline")
    parser.add_argument("--complete-evidence", action="store_true", help="include small redacted response excerpts for authorized private reports")
    parser.add_argument("--output", help="write JSON payload to file")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    args = parser.parse_args(argv)

    mutation_count = sum(bool(item) for item in [args.param, args.json_field, args.json_path, args.form_field, args.header_name, args.path_placeholder])
    if mutation_count != 1:
        print("error: provide exactly one mutation target: --param, --json-field, --json-path, --form-field, --header-name, or --path-placeholder", file=sys.stderr)
        return 2
    try:
        headers = parse_headers(args.header)
        values = load_values(args)
        build_spec(args, headers)
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
    if args.output:
        Path(args.output).write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
