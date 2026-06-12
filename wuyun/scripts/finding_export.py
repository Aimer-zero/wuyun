#!/usr/bin/env python3
"""Validate and export Wuyun finding bundles as JSON, SARIF, Markdown, or HTML."""
from __future__ import annotations

import argparse
import html
import json
import sys
from pathlib import Path

LEVEL_MAP = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "informational": "note"}


def load_bundle(path: str | None) -> dict:
    raw = sys.stdin.read() if not path or path == "-" else Path(path).read_text(encoding="utf-8", errors="replace")
    data = json.loads(raw)
    if isinstance(data, list):
        data = {"findings": data}
    if "findings" not in data:
        data = {"findings": data.get("results", []) if isinstance(data, dict) else []}
    return data


def normalize_finding(item: dict, idx: int) -> dict:
    return {
        "id": str(item.get("id") or item.get("rule") or f"wuyun.imported.{idx}"),
        "title": str(item.get("title") or item.get("message") or item.get("description") or "Wuyun finding"),
        "severity": str(item.get("severity") or "informational").lower(),
        "confidence": str(item.get("confidence") or "medium").lower(),
        "category": str(item.get("category") or item.get("source_tool") or "general"),
        "path": str(item.get("path") or item.get("file") or ""),
        "line": int(item.get("line") or item.get("start_line") or 1),
        "evidence": str(item.get("evidence") or item.get("snippet") or ""),
        "remediation": str(item.get("remediation") or item.get("fix") or "Review and remediate if confirmed."),
        **{k: v for k, v in item.items() if k not in {"id", "title", "severity", "confidence", "category", "path", "file", "line", "start_line", "evidence", "snippet", "remediation", "fix"}},
    }


def normalize_bundle(bundle: dict) -> dict:
    findings = [normalize_finding(item, idx) for idx, item in enumerate(bundle.get("findings", [])) if isinstance(item, dict)]
    return {**bundle, "summary": {**bundle.get("summary", {}), "finding_count": len(findings)}, "findings": findings}


def to_sarif(bundle: dict) -> dict:
    rules = {}
    results = []
    for f in bundle.get("findings", []):
        rule_id = f["id"]
        rules.setdefault(rule_id, {
            "id": rule_id,
            "name": f["title"][:80],
            "shortDescription": {"text": f["title"]},
            "fullDescription": {"text": f.get("remediation", "")},
            "properties": {"category": f.get("category", "general"), "confidence": f.get("confidence", "medium")},
        })
        location = {"physicalLocation": {"artifactLocation": {"uri": f.get("path") or "wuyun-report"}, "region": {"startLine": max(1, int(f.get("line") or 1))}}}
        results.append({
            "ruleId": rule_id,
            "level": LEVEL_MAP.get(f.get("severity", "informational"), "note"),
            "message": {"text": f"{f['title']}\n\nEvidence: {f.get('evidence','')}\n\nRemediation: {f.get('remediation','')}"[:4000]},
            "locations": [location],
            "properties": {"severity": f.get("severity"), "confidence": f.get("confidence"), "category": f.get("category")},
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Wuyun", "informationUri": "https://github.com/Aimer-zero/wuyun", "rules": list(rules.values())}},
            "results": results,
        }],
    }


def to_markdown(bundle: dict) -> str:
    lines = ["# Wuyun Findings", "", f"- Findings: `{len(bundle.get('findings', []))}`", "", "| Severity | Confidence | Rule | Location | Title |", "|---|---|---|---|---|"]
    for f in bundle.get("findings", []):
        loc = f"{f.get('path','')}:{f.get('line',1)}" if f.get("path") else ""
        title = f["title"].replace("|", "\\|")
        lines.append(f"| {f.get('severity')} | {f.get('confidence')} | `{f['id']}` | `{loc}` | {title} |")
    return "\n".join(lines) + "\n"


def to_html(bundle: dict) -> str:
    rows = []
    for f in bundle.get("findings", []):
        rows.append("<tr>" + "".join([
            f"<td>{html.escape(str(f.get('severity','')))}</td>",
            f"<td>{html.escape(str(f.get('confidence','')))}</td>",
            f"<td><code>{html.escape(f['id'])}</code></td>",
            f"<td><code>{html.escape(str(f.get('path','')))}:{html.escape(str(f.get('line',1)))}</code></td>",
            f"<td>{html.escape(f['title'])}</td>",
            f"<td>{html.escape(f.get('remediation',''))}</td>",
        ]) + "</tr>")
    return """<!doctype html><meta charset='utf-8'><title>Wuyun Findings</title>
<style>body{font-family:system-ui,sans-serif;margin:2rem}table{border-collapse:collapse;width:100%}td,th{border:1px solid #ddd;padding:.45rem;vertical-align:top}th{background:#f6f8fa}</style>
<h1>Wuyun Findings</h1><p>Findings: <strong>%d</strong></p><table><thead><tr><th>Severity</th><th>Confidence</th><th>Rule</th><th>Location</th><th>Title</th><th>Remediation</th></tr></thead><tbody>%s</tbody></table>""" % (len(bundle.get("findings", [])), "".join(rows))


def write(path: str | None, content: str) -> None:
    if not path or path == "-":
        print(content, end="")
    else:
        Path(path).write_text(content, encoding="utf-8")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Export Wuyun findings to JSON/SARIF/Markdown/HTML.")
    parser.add_argument("input", nargs="?", default="-", help="finding JSON file or stdin")
    parser.add_argument("--format", choices=["json", "sarif", "markdown", "html"], default="json")
    parser.add_argument("--output", "-o", help="output file; defaults to stdout")
    parser.add_argument("--validate", action="store_true", help="normalize and fail if required fields are absent")
    args = parser.parse_args(argv)
    bundle = normalize_bundle(load_bundle(args.input))
    if args.validate:
        missing = [f for f in bundle.get("findings", []) if not all(f.get(k) for k in ("id", "title", "severity", "confidence", "category"))]
        if missing:
            print(f"error: {len(missing)} findings missing required fields", file=sys.stderr)
            return 1
    if args.format == "json":
        content = json.dumps(bundle, ensure_ascii=False, indent=2) + "\n"
    elif args.format == "sarif":
        content = json.dumps(to_sarif(bundle), ensure_ascii=False, indent=2) + "\n"
    elif args.format == "markdown":
        content = to_markdown(bundle)
    else:
        content = to_html(bundle)
    write(args.output, content)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
