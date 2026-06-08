#!/usr/bin/env python3
"""Generate authorized IDOR/BOLA validation cases without sending requests."""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.parse
from pathlib import Path


ROUTE_RE = re.compile(
    r"(?<![A-Za-z0-9])/(?:api/|v\d+/|admin/|internal/|auth/|oauth/|graphql|upload|files|webhook|"
    r"users?/|orders?/|tenants?/|accounts?/|orgs?/|workspaces?/|projects?/|invoices?/)"
    r"[A-Za-z0-9._~:/{}?#\[\]@!$&'()*+,;=%-]*"
)
ID_HINT_RE = re.compile(r"(?i)(?:^|[/_{:-])(?:id|user|account|org|tenant|workspace|project|invoice|order|file)(?:id)?(?:$|[}/_:-])")


def read_routes(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8", errors="replace")
    routes = set(ROUTE_RE.findall(text))
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


def build_cases(args: argparse.Namespace) -> dict:
    routes = read_routes(Path(args.routes).resolve())
    owned = [item.strip() for chunk in args.owned_value for item in chunk.split(",") if item.strip()]
    alternate = [item.strip() for chunk in args.alternate_value for item in chunk.split(",") if item.strip()]
    candidates = [route for route in routes if route_has_object_hint(route)]
    cases = []
    for route in candidates[: args.max_cases]:
        url = normalize_url(args.base_url, route)
        cases.append({
            "name": f"idor-bola-{len(cases) + 1}",
            "route": route,
            "url": url,
            "method": args.method.upper(),
            "baseline_identity": args.baseline_identity,
            "probe_identity": args.probe_identity,
            "owned_values": owned,
            "alternate_values": alternate,
            "expected_secure_result": "Probe identity receives 401/403/404 or an equivalent no-access response without sensitive object data.",
            "diff_signals": ["status", "content-length", "body-hash", "error-marker", "object-owner-marker"],
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
        print(f"  baseline=`{case['baseline_identity']}` probe=`{case['probe_identity']}`")
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
