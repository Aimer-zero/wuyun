#!/usr/bin/env python3
"""Compare two HTTP messages or response bodies for security triage.

Designed for role/account diffing. It does not send requests.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SENSITIVE_HEADER = re.compile(r"(?i)authorization|cookie|set-cookie|x-api-key|token|secret|password")
SENSITIVE_JSON_KEY = re.compile(r"(?i)token|secret|password|credential|accessKey|session|cookie")


@dataclass
class HttpMessage:
    start: str
    headers: dict[str, str]
    body: str
    json_body: Any | None


def format_value(key: str, value: str, complete: bool = False) -> str:
    if complete:
        return value
    if SENSITIVE_HEADER.search(key) or SENSITIVE_JSON_KEY.search(key):
        if len(value) <= 8:
            return f"<compact len={len(value)}>"
        return f"{value[:4]}…{value[-4:]} (len={len(value)})"
    if len(value) > 160:
        return value[:120] + "…"
    return value


def parse_message(text: str) -> HttpMessage:
    normalized = text.replace("\r\n", "\n")
    head, sep, body = normalized.partition("\n\n")
    if not sep:
        head, body = "", normalized
    lines = head.splitlines() if head else []
    start = lines[0] if lines and (lines[0].startswith("HTTP/") or re.match(r"^[A-Z]+\s+\S+\s+HTTP/", lines[0])) else ""
    headers: dict[str, str] = {}
    for line in lines[1 if start else 0:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()
    json_body = None
    stripped = body.strip()
    if stripped:
        try:
            json_body = json.loads(stripped)
        except json.JSONDecodeError:
            json_body = None
    return HttpMessage(start, headers, body, json_body)


def flatten_json(value: Any, prefix: str = "") -> dict[str, str]:
    out: dict[str, str] = {}
    if isinstance(value, dict):
        for key, child in value.items():
            full = f"{prefix}.{key}" if prefix else str(key)
            out.update(flatten_json(child, full))
    elif isinstance(value, list):
        out[prefix or "[]"] = f"<list len={len(value)}>"
        for idx, child in enumerate(value[:20]):
            full = f"{prefix}[{idx}]" if prefix else f"[{idx}]"
            out.update(flatten_json(child, full))
    else:
        out[prefix or "<root>"] = str(value)
    return out


def diff_dict(a: dict[str, str], b: dict[str, str], complete: bool = False) -> list[tuple[str, str, str, str]]:
    rows: list[tuple[str, str, str, str]] = []
    keys = sorted(set(a) | set(b))
    for key in keys:
        av = a.get(key)
        bv = b.get(key)
        if av == bv:
            continue
        if av is None:
            rows.append(("added", key, "", format_value(key, bv or "", complete=complete)))
        elif bv is None:
            rows.append(("removed", key, format_value(key, av, complete=complete), ""))
        else:
            rows.append(("changed", key, format_value(key, av, complete=complete), format_value(key, bv, complete=complete)))
    return rows


def summarize(a: HttpMessage, b: HttpMessage, complete: bool = False) -> dict[str, Any]:
    rows: dict[str, Any] = {
        "start_changed": a.start != b.start,
        "start_a": a.start,
        "start_b": b.start,
        "header_diff": diff_dict(a.headers, b.headers, complete=complete),
        "body_len_a": len(a.body),
        "body_len_b": len(b.body),
        "body_len_delta": len(b.body) - len(a.body),
        "json_diff": [],
    }
    if a.json_body is not None or b.json_body is not None:
        rows["json_diff"] = diff_dict(flatten_json(a.json_body), flatten_json(b.json_body), complete=complete) if a.json_body is not None and b.json_body is not None else [("changed", "<json-parse>", str(a.json_body is not None), str(b.json_body is not None))]
    return rows


def print_markdown(summary: dict[str, Any]) -> None:
    print("# HTTP Message Diff")
    print()
    print("- Execution: local comparison only")
    print(f"- Body lengths: `{summary['body_len_a']}` vs `{summary['body_len_b']}` (delta `{summary['body_len_delta']}`)")
    if summary["start_changed"]:
        print(f"- Start line changed: `{summary['start_a']}` → `{summary['start_b']}`")
    print()
    for title, rows in (("Header differences", summary["header_diff"]), ("JSON differences", summary["json_diff"])):
        print(f"## {title}")
        if not rows:
            print("- None")
            print()
            continue
        print("| Type | Key | A | B |")
        print("|---|---|---|---|")
        for typ, key, av, bv in rows[:200]:
            print(f"| {typ} | `{key}` | `{av}` | `{bv}` |")
        if len(rows) > 200:
            print(f"\n_Truncated {len(rows) - 200} additional differences._")
        print()
    print("## Triage Hint")
    print("Use differences to identify role/account-dependent fields; confirm whether any changed field crosses an intended authorization, tenant, or workflow boundary.")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Diff two local HTTP messages/responses.")
    parser.add_argument("a", help="first HTTP message/body file")
    parser.add_argument("b", help="second HTTP message/body file")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    parser.add_argument("--complete", action="store_true", help="emit complete in-scope values for authorized private reports")
    args = parser.parse_args(argv)
    try:
        msg_a = parse_message(Path(args.a).read_text(encoding="utf-8", errors="replace"))
        msg_b = parse_message(Path(args.b).read_text(encoding="utf-8", errors="replace"))
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    summary = summarize(msg_a, msg_b, complete=args.complete)
    if args.json:
        print(json.dumps(summary, ensure_ascii=False, indent=2))
    else:
        print_markdown(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
