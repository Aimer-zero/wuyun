#!/usr/bin/env python3
"""Generate authorized IDOR/BOLA validation cases without sending requests."""
from __future__ import annotations

import argparse
import json
import re
import shlex
import sys
import urllib.parse
from pathlib import Path
from typing import Any


ROUTE_RE = re.compile(
    r"(?<![A-Za-z0-9])/(?:api/|v\d+/|admin/|internal/|auth/|oauth/|graphql|upload|files|webhook|"
    r"users?/|orders?/|tenants?/|accounts?/|orgs?/|workspaces?/|projects?/|invoices?/)"
    r"[A-Za-z0-9._~:/{}?#\[\]@!$&'()*+,;=%-]*"
)
ID_HINT_RE = re.compile(r"(?i)(?:^|[/_{:-])(?:id|user|account|org|tenant|workspace|project|invoice|order|file)(?:id)?(?:$|[}/_:-])")
QUERY_ID_RE = re.compile(r"(?i)(?:^|[?&])([A-Za-z0-9_.-]*(?:id|user|account|org|tenant|workspace|project|invoice|order|file)[A-Za-z0-9_.-]*)=")
PLACEHOLDER_RE = re.compile(r"(:[A-Za-z_][A-Za-z0-9_]*|\{[A-Za-z_][A-Za-z0-9_]*\}|<[^>]+>|\d{2,})")


def collect_routes_from_json(value: Any) -> set[str]:
    routes: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            if isinstance(key, str) and key.startswith("/"):
                routes.add(key)
            if isinstance(child, str) and key in {"route", "path", "url", "endpoint", "evidence"}:
                routes.update(ROUTE_RE.findall(child))
                if child.startswith("/") or child.startswith("http://") or child.startswith("https://"):
                    routes.add(child)
            routes.update(collect_routes_from_json(child))
    elif isinstance(value, list):
        for item in value:
            routes.update(collect_routes_from_json(item))
    elif isinstance(value, str):
        routes.update(ROUTE_RE.findall(value))
        if value.startswith("/") or value.startswith("http://") or value.startswith("https://"):
            routes.add(value)
    return routes


def read_routes(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8", errors="replace")
    routes = set(ROUTE_RE.findall(text))
    try:
        routes.update(collect_routes_from_json(json.loads(text)))
    except json.JSONDecodeError:
        pass
    for line in text.splitlines():
        item = line.strip()
        if item.startswith("/"):
            routes.add(item)
    return sorted(routes)


def route_has_object_hint(route: str) -> bool:
    parts = [part for part in re.split(r"/+", route) if part]
    return any(
        ID_HINT_RE.search(part)
        or part.startswith(":")
        or (part.startswith("{") and part.endswith("}"))
        or re.fullmatch(r"\d+", part)
        for part in parts
    )


def normalize_url(base_url: str, route: str) -> str:
    if route.startswith("http://") or route.startswith("https://"):
        return route
    return urllib.parse.urljoin(base_url.rstrip("/") + "/", route.lstrip("/"))


def split_values(chunks: list[str], fallback: list[str]) -> list[str]:
    values = [item.strip() for chunk in chunks for item in chunk.split(",") if item.strip()]
    return values or fallback


def find_path_placeholder(route: str) -> str | None:
    for match in PLACEHOLDER_RE.finditer(urllib.parse.urlparse(route).path):
        token = match.group(1)
        if token.startswith(":"):
            return token
        if token.startswith("{") and token.endswith("}"):
            return token
        if token.startswith("<") and token.endswith(">"):
            return token
        if token.isdigit():
            return token
    return None


def find_query_param(route: str) -> str | None:
    parsed = urllib.parse.urlparse(route)
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    for key in query:
        if ID_HINT_RE.search(key):
            return key
    match = QUERY_ID_RE.search(route)
    return match.group(1) if match else None


def choose_mutation(route: str) -> dict[str, str] | None:
    query_param = find_query_param(route)
    if query_param:
        return {"kind": "query-param", "flag": "--param", "target": query_param}
    placeholder = find_path_placeholder(route)
    if placeholder:
        return {"kind": "path-placeholder", "flag": "--path-placeholder", "target": placeholder}
    return None


def command_for_case(case: dict, scope_host: str, values: list[str], active: bool = False) -> list[str]:
    command = [
        "python3",
        "wuyun-web-api-audit/scripts/active_http_validator.py",
        "--url",
        case["url"],
        "--method",
        case["method"],
        "--scope-host",
        scope_host,
        case["mutation"]["flag"],
        case["mutation"]["target"],
        "--baseline-value",
        case["owned_values"][0],
        "--values",
        ",".join(values),
        "--delay",
        "1.0",
        "--max-requests",
        str(min(len(values), 10)),
    ]
    if active:
        command.append("--authorize-active-testing")
    return command


def build_cases(args: argparse.Namespace) -> dict:
    routes = read_routes(Path(args.routes).resolve())
    owned = split_values(args.owned_value, ["<owned-object-id>"])
    alternate = split_values(args.alternate_value, ["<other-owned-object-id>", "<synthetic-no-access-id>"])
    candidates = [route for route in routes if route_has_object_hint(route)]
    cases = []
    for route in candidates[: args.max_cases]:
        url = normalize_url(args.base_url, route)
        mutation = choose_mutation(route)
        if mutation is None:
            continue
        scope_host = urllib.parse.urlparse(url).hostname or "<scope-host>"
        cases.append({
            "name": f"idor-bola-{len(cases) + 1}",
            "route": route,
            "url": url,
            "method": args.method.upper(),
            "mutation": mutation,
            "baseline_identity": args.baseline_identity,
            "probe_identity": args.probe_identity,
            "owned_values": owned,
            "alternate_values": alternate,
            "expected_secure_result": "Probe identity receives 401/403/404 or an equivalent no-access response without sensitive object data.",
            "diff_signals": ["status", "content-length", "body-hash", "error-marker", "object-owner-marker"],
            "dry_run_command": command_for_case({"url": url, "method": args.method.upper(), "mutation": mutation, "owned_values": owned}, scope_host, alternate, active=False),
            "authorized_active_command": command_for_case({"url": url, "method": args.method.upper(), "mutation": mutation, "owned_values": owned}, scope_host, alternate, active=True),
            "review_checklist": [
                "Confirm both identities are controlled test accounts.",
                "Confirm owned and alternate object values are synthetic or in-scope.",
                "Run the dry-run command first and review the exact request count.",
                "Execute only one case at a time with an explicit scope host.",
                "Use request_diff.py on captured baseline/probe messages before claiming impact.",
            ],
            "runner_hint": (
                "Use active_http_validator.py with --authorize-active-testing only after replacing placeholders, "
                "confirming owned accounts/synthetic objects, and setting --scope-host."
            ),
        })
    return {
        "source": str(Path(args.routes).resolve()),
        "base_url": args.base_url,
        "routes_seen": len(routes),
        "object_route_candidates": len(candidates),
        "cases": cases,
        "limits": [
            "case generation only; no requests are sent",
            "use owned accounts and synthetic records",
            "do not access or retain other users' data",
        ],
    }


def print_markdown(payload: dict) -> None:
    print("# Wuyun IDOR/BOLA Case Generator")
    print()
    print(f"- Source: `{payload['source']}`")
    print(f"- Routes seen: `{payload['routes_seen']}`")
    print(f"- Object candidates: `{payload['object_route_candidates']}`")
    print("## Cases")
    for case in payload["cases"]:
        print(f"- `{case['name']}` `{case['method']} {case['url']}` route `{case['route']}`")
        print(f"  mutation=`{case['mutation']['kind']}:{case['mutation']['target']}` baseline=`{case['baseline_identity']}` probe=`{case['probe_identity']}`")
        print(f"  dry-run: `{shlex.join(case['dry_run_command'])}`")
    print("## Limits")
    for item in payload["limits"]:
        print(f"- {item}")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Generate IDOR/BOLA validation case plans from routes.")
    parser.add_argument("routes", help="route wordlist, JS extraction output, HAR, or text artifact")
    parser.add_argument("--base-url", required=True, help="authorized base URL used to form case URLs")
    parser.add_argument("--method", default="GET")
    parser.add_argument("--baseline-identity", default="owned-account-a")
    parser.add_argument("--probe-identity", default="owned-account-b")
    parser.add_argument("--owned-value", action="append", default=[], help="comma-separated object IDs owned by baseline identity")
    parser.add_argument("--alternate-value", action="append", default=[], help="comma-separated object IDs owned by probe identity or synthetic no-access cases")
    parser.add_argument("--max-cases", type=int, default=50)
    parser.add_argument("--output", help="write JSON case plan")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    path = Path(args.routes)
    if not path.exists():
        print(f"error: routes file does not exist: {path}", file=sys.stderr)
        return 2
    payload = build_cases(args)
    if args.output:
        Path(args.output).write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print_markdown(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
