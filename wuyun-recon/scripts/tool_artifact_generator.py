#!/usr/bin/env python3
"""Generate importable or reviewable artifacts for external security tools."""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.parse
from pathlib import Path


SENSITIVE_HEADER_RE = re.compile(r"(?i)authorization|cookie|x-api-key|token|secret|password")


def parse_headers(items: list[str]) -> dict[str, str]:
    headers = {}
    for item in items:
        if ":" not in item:
            raise ValueError(f"header must be 'Name: value': {item}")
        key, value = item.split(":", 1)
        headers[key.strip()] = value.strip()
    return headers


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    return {
        key: "<replace-with-authorized-value>" if SENSITIVE_HEADER_RE.search(key) else value
        for key, value in headers.items()
    }


def http_collection(args: argparse.Namespace, headers: dict[str, str]) -> str:
    lines = [f"{args.method.upper()} {args.url} HTTP/1.1"]
    parsed = urllib.parse.urlparse(args.url)
    lines.append(f"Host: {parsed.netloc}")
    for key, value in redact_headers(headers).items():
        lines.append(f"{key}: {value}")
    if args.body:
        lines.extend(["", args.body])
    else:
        lines.append("")
    return "\n".join(lines) + "\n"


def nuclei_template(args: argparse.Namespace, headers: dict[str, str]) -> str:
    parsed = urllib.parse.urlparse(args.url)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    header_lines = "\n".join(f"        {key}: {value}" for key, value in redact_headers(headers).items())
    return f"""id: wuyun-custom-review

info:
  name: Wuyun custom low-impact review template
  author: wuyun
  severity: info
  description: Owner-reviewed template skeleton. Replace matchers and payloads with authorized, minimal checks.

http:
  - method: {args.method.upper()}
    path:
      - "{{{{BaseURL}}}}{path}"
    headers:
{header_lines or "      X-Wuyun-Review: authorized"}
    matchers:
      - type: status
        status:
          - 200
          - 401
          - 403
          - 404
"""


def sqlmap_plan(args: argparse.Namespace, headers: dict[str, str]) -> str:
    cmd = [
        "sqlmap",
        "-u", args.url,
        "--batch",
        "--risk=1",
        "--level=1",
        "--threads=1",
        "--delay=1",
        "--timeout=10",
        "--flush-session",
    ]
    if args.param:
        cmd.extend(["-p", args.param])
    if headers:
        safe = "; ".join(f"{key}: {value}" for key, value in redact_headers(headers).items())
        cmd.extend(["--headers", safe])
    return " ".join(shell_quote(part) for part in cmd) + "\n"


def ffuf_plan(args: argparse.Namespace) -> str:
    wordlist = args.wordlist or "routes.txt"
    url = args.url if "FUZZ" in args.url else args.url.rstrip("/") + "/FUZZ"
    cmd = ["ffuf", "-w", wordlist, "-u", url, "-rate", str(args.rate), "-mc", "200,204,301,302,307,401,403"]
    return " ".join(shell_quote(part) for part in cmd) + "\n"


def shell_quote(value: str) -> str:
    if value and all(ch.isalnum() or ch in "@%_+=:,./-{}?&" for ch in value):
        return value
    return "'" + value.replace("'", "'\\''") + "'"


def build(args: argparse.Namespace) -> dict:
    headers = parse_headers(args.header)
    if args.mode == "http-collection":
        body = http_collection(args, headers)
    elif args.mode == "nuclei-template":
        body = nuclei_template(args, headers)
    elif args.mode == "sqlmap-plan":
        body = sqlmap_plan(args, headers)
    elif args.mode == "ffuf-plan":
        body = ffuf_plan(args)
    else:
        raise ValueError(f"unsupported mode: {args.mode}")
    return {
        "mode": args.mode,
        "url": args.url,
        "artifact": body,
        "limits": [
            "artifact generation only; no external tool is executed",
            "replace placeholders only within written authorization and scope",
            "keep rates low and validate findings manually",
        ],
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Generate Burp/Caido/http, nuclei, sqlmap, or ffuf artifacts.")
    parser.add_argument("--mode", required=True, choices=["http-collection", "nuclei-template", "sqlmap-plan", "ffuf-plan"])
    parser.add_argument("--url", required=True)
    parser.add_argument("--method", default="GET")
    parser.add_argument("--header", action="append", default=[])
    parser.add_argument("--body")
    parser.add_argument("--param")
    parser.add_argument("--wordlist")
    parser.add_argument("--rate", type=int, default=20)
    parser.add_argument("--output")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        payload = build(args)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.output:
        Path(args.output).write_text(payload["artifact"], encoding="utf-8")
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(payload["artifact"], end="")
        print("# Limits")
        for item in payload["limits"]:
            print(f"# - {item}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
