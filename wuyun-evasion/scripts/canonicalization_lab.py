#!/usr/bin/env python3
"""Generate benign canonicalization variants for local parser-mismatch review."""
from __future__ import annotations

import argparse
import html
import json
import urllib.parse


def mixed_case(value: str) -> str:
    return "".join(ch.upper() if idx % 2 else ch.lower() for idx, ch in enumerate(value))


def percent_encode_all(value: str) -> str:
    return "".join(f"%{byte:02X}" for byte in value.encode("utf-8"))


def variants(literal: str, param: str) -> list[dict[str, str]]:
    url_once = percent_encode_all(literal)
    url_twice = percent_encode_all(url_once)
    unicode_escape = "".join(f"\\u{ord(ch):04x}" for ch in literal)
    rows = [
        {"name": "plain", "value": literal, "example_query": urllib.parse.urlencode({param: literal})},
        {"name": "url-encoded", "value": url_once, "example_query": f"{param}={url_once}"},
        {"name": "double-url-encoded", "value": url_twice, "example_query": f"{param}={url_twice}"},
        {"name": "html-entity", "value": html.escape(literal), "example_query": urllib.parse.urlencode({param: html.escape(literal)})},
        {"name": "unicode-escape", "value": unicode_escape, "example_query": urllib.parse.urlencode({param: unicode_escape})},
        {"name": "mixed-case", "value": mixed_case(literal), "example_query": urllib.parse.urlencode({param: mixed_case(literal)})},
        {"name": "duplicate-param", "value": literal, "example_query": f"{param}={urllib.parse.quote(literal)}&{param}={urllib.parse.quote(literal + '_B')}"},
    ]
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate local benign canonicalization variants.")
    parser.add_argument("--literal", default="WUYUN_CANONICALIZATION_TEST")
    parser.add_argument("--param", default="q")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    payload = {
        "literal": args.literal,
        "param": args.param,
        "variants": variants(args.literal, args.param),
        "limits": [
            "local/lab canonicalization review only",
            "do not combine with exploit payloads or public-target bypass attempts",
            "compare one variant at a time with low request counts when authorized",
        ],
    }
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print("# Wuyun Canonicalization Lab")
        print()
        for row in payload["variants"]:
            print(f"- `{row['name']}` value `{row['value']}` query `{row['example_query']}`")
        print("## Limits")
        for item in payload["limits"]:
            print(f"- {item}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
