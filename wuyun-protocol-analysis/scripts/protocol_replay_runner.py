#!/usr/bin/env python3
"""Authorized protocol replay runner for Wuyun.

Default mode is dry-run. Execution requires --authorize-protocol-replay and a
matching --scope-host. Supports HTTP JSON, GraphQL, JSON-RPC, and optional
WebSocket replay when the `websockets` Python module is installed.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class ReplayResult:
    label: str
    status: int | None
    elapsed_ms: int
    response_len: int
    response_sha256_12: str
    content_type: str
    error: str | None


def compact_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    query = "<query-redacted>" if parsed.query else ""
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, "<fragment-redacted>" if parsed.fragment else ""))


def enforce_scope(url: str, scope_hosts: list[str]) -> None:
    host = urllib.parse.urlparse(url).hostname or ""
    if host.lower() not in {item.lower() for item in scope_hosts}:
        raise ValueError(f"target host `{host}` is not in --scope-host allowlist")


def body_summary(body: bytes) -> tuple[int, str]:
    return len(body), hashlib.sha256(body).hexdigest()[:12]


def http_post_json(url: str, headers: dict[str, str], body: Any, timeout: float, label: str) -> ReplayResult:
    payload = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    merged_headers = {"content-type": "application/json", **headers}
    request = urllib.request.Request(url, data=payload, headers=merged_headers, method="POST")
    start = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            response_body = response.read(500_000)
            elapsed = int((time.monotonic() - start) * 1000)
            length, digest = body_summary(response_body)
            return ReplayResult(label, response.status, elapsed, length, digest, response.headers.get("content-type", ""), None)
    except urllib.error.HTTPError as exc:
        response_body = exc.read(500_000)
        elapsed = int((time.monotonic() - start) * 1000)
        length, digest = body_summary(response_body)
        return ReplayResult(label, exc.code, elapsed, length, digest, exc.headers.get("content-type", "") if exc.headers else "", None)
    except Exception as exc:  # noqa: BLE001 - summarize one failed probe and continue
        elapsed = int((time.monotonic() - start) * 1000)
        return ReplayResult(label, None, elapsed, 0, "", "", f"{type(exc).__name__}: {exc}")


async def websocket_replay(case: dict[str, Any], timeout: float) -> list[ReplayResult]:
    try:
        import websockets
    except Exception as exc:  # noqa: BLE001
        return [ReplayResult("websocket-dependency", None, 0, 0, "", "", f"websockets module unavailable: {exc}")]

    url = case["url"]
    headers = case.get("headers", {})
    results: list[ReplayResult] = []
    start = time.monotonic()
    try:
        async with websockets.connect(url, extra_headers=headers, open_timeout=timeout) as ws:
            for item in case.get("messages", []):
                label = str(item.get("label", f"message-{len(results) + 1}"))
                data = item.get("data", "")
                sent_at = time.monotonic()
                await ws.send(data)
                try:
                    response = await asyncio.wait_for(ws.recv(), timeout=timeout)
                    raw = response.encode("utf-8", errors="replace") if isinstance(response, str) else bytes(response)
                    length, digest = body_summary(raw[:500_000])
                    results.append(ReplayResult(label, 101, int((time.monotonic() - sent_at) * 1000), length, digest, "websocket-message", None))
                except asyncio.TimeoutError:
                    results.append(ReplayResult(label, 101, int((time.monotonic() - sent_at) * 1000), 0, "", "websocket-message", "receive timeout"))
    except Exception as exc:  # noqa: BLE001
        results.append(ReplayResult("websocket-connect", None, int((time.monotonic() - start) * 1000), 0, "", "", f"{type(exc).__name__}: {exc}"))
    return results


def build_http_body(case_type: str, base: dict[str, Any], probe: dict[str, Any] | None) -> Any:
    if case_type == "graphql":
        body = {
            "query": base.get("query", ""),
            "variables": base.get("variables", {}),
            "operationName": base.get("operationName"),
        }
        if probe:
            body["variables"] = {**body.get("variables", {}), **probe.get("variables", {})}
            if "query" in probe:
                body["query"] = probe["query"]
            if "operationName" in probe:
                body["operationName"] = probe["operationName"]
        return {k: v for k, v in body.items() if v is not None}
    if case_type == "json-rpc":
        body = dict(base)
        if probe:
            body.update(probe.get("body", {}))
            if "params" in probe:
                body["params"] = probe["params"]
            if "method" in probe:
                body["method"] = probe["method"]
        return body
    body = dict(base)
    if probe:
        body.update(probe.get("body", {}))
    return body


def dry_run(case: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": "dry-run",
        "type": case.get("type"),
        "target": compact_url(case.get("url", "")),
        "planned": len(case.get("probes", [])) + (len(case.get("messages", [])) if case.get("type") == "websocket" else 1),
        "limits": default_limits(),
    }


def default_limits() -> list[str]:
    return [
        "explicit authorization and scope host required for execution",
        "response body capped at 500KB and summarized by length/hash",
        "no captured traffic replay unless represented in the reviewed case file",
        "use owned accounts, synthetic records, and low request counts",
    ]


async def execute(case: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    enforce_scope(case["url"], args.scope_host)
    case_type = case.get("type", "http-json")
    if case_type == "websocket":
        results = await websocket_replay(case, args.timeout)
    else:
        if case_type not in {"http-json", "graphql", "json-rpc"}:
            raise ValueError(f"unsupported case type: {case_type}")
        headers = case.get("headers", {})
        base = case.get("baseline", {})
        results = [http_post_json(case["url"], headers, build_http_body(case_type, base, None), args.timeout, "baseline")]
        for index, probe in enumerate(case.get("probes", [])[: args.max_probes], start=1):
            time.sleep(args.delay)
            label = str(probe.get("label", f"probe-{index}"))
            results.append(http_post_json(case["url"], headers, build_http_body(case_type, base, probe), args.timeout, label))
    baseline = results[0] if results else None
    comparisons = []
    if baseline:
        for result in results[1:]:
            comparisons.append({
                "label": result.label,
                "status_changed": result.status != baseline.status,
                "length_delta": result.response_len - baseline.response_len,
                "hash_changed": result.response_sha256_12 != baseline.response_sha256_12,
            })
    return {
        "status": "executed",
        "type": case_type,
        "target": compact_url(case["url"]),
        "results": [result.__dict__ for result in results],
        "comparisons": comparisons,
        "limits": default_limits(),
    }


def print_markdown(payload: dict[str, Any]) -> None:
    print("# Wuyun Protocol Replay Runner")
    print()
    print(f"- Status: `{payload['status']}`")
    print(f"- Type: `{payload.get('type')}`")
    print(f"- Target: `{payload.get('target')}`")
    print()
    if payload["status"] == "dry-run":
        print(f"- Planned operations: `{payload['planned']}`")
        print("- Add `--authorize-protocol-replay` and matching `--scope-host` to execute.")
    else:
        print("## Results")
        for row in payload["results"]:
            print(f"- `{row['label']}` -> status `{row['status']}` len `{row['response_len']}` hash `{row['response_sha256_12']}` type `{row['content_type']}` error `{row['error'] or ''}`")
        print()
        print("## Comparisons")
        for row in payload["comparisons"]:
            print(f"- `{row['label']}`: status_changed=`{row['status_changed']}` length_delta=`{row['length_delta']}` hash_changed=`{row['hash_changed']}`")
    print()
    print("## Limits")
    for item in payload["limits"]:
        print(f"- {item}")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Authorized protocol replay and permission test runner.")
    parser.add_argument("case", help="JSON replay case file")
    parser.add_argument("--authorize-protocol-replay", action="store_true", help="confirm written authorization for this exact protocol replay")
    parser.add_argument("--scope-host", action="append", default=[], help="authorized host allowlist")
    parser.add_argument("--delay", type=float, default=1.0)
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--max-probes", type=int, default=10)
    parser.add_argument("--json", action="store_true", help="emit JSON")
    args = parser.parse_args(argv)

    try:
        case = json.loads(Path(args.case).read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: failed to read case file: {exc}", file=sys.stderr)
        return 2
    if "url" not in case:
        print("error: case file must include url", file=sys.stderr)
        return 2
    if args.delay < 0.2:
        print("error: --delay must be >= 0.2 seconds", file=sys.stderr)
        return 2
    if args.max_probes > 50:
        print("error: --max-probes must be <= 50", file=sys.stderr)
        return 2

    if not args.authorize_protocol_replay:
        payload = dry_run(case)
    else:
        if not args.scope_host:
            print("error: --scope-host is required with --authorize-protocol-replay", file=sys.stderr)
            return 2
        try:
            payload = asyncio.run(execute(case, args))
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
