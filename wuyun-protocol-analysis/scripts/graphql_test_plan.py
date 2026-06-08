#!/usr/bin/env python3
"""Generate safe GraphQL review and replay case plans."""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


OP_RE = re.compile(r"\b(query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]*)?")


def load_operations(path: str | None) -> list[dict[str, Any]]:
    if not path:
        return []
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    operations = []
    for match in OP_RE.finditer(text):
        operations.append({"kind": match.group(1), "name": match.group(2) or "<anonymous>"})
    return operations


def build_case(args: argparse.Namespace) -> dict[str, Any]:
    baseline_query = args.query or "query WuyunTypename { __typename }"
    probes = [
        {
            "label": "typename-smoke",
            "query": "query WuyunTypename { __typename }",
            "variables": {},
        },
        {
            "label": "introspection-availability-check",
            "query": "query WuyunSchemaCheck { __schema { queryType { name } mutationType { name } } }",
            "variables": {},
        },
    ]
    if args.include_mutation_smoke:
        probes.append({
            "label": "mutation-shape-smoke",
            "query": "mutation WuyunMutationShape { __typename }",
            "variables": {},
        })
    if args.include_batch_review:
        probes.append({
            "label": "batch-policy-review",
            "query": "query WuyunBatchReview { __typename }",
            "variables": {"wuyun_note": "review batch limits with at most three synthetic operations"},
        })
    return {
        "type": "graphql",
        "url": args.url,
        "headers": {},
        "baseline": {
            "query": baseline_query,
            "variables": {},
            "operationName": None,
        },
        "probes": probes,
        "review_plan": {
            "operations_from_file": load_operations(args.operations),
            "checks": [
                "introspection exposure and authorization",
                "field-level authorization on object references",
                "mutation side-effect protections using synthetic records",
                "query depth/complexity/rate limits",
                "batch request policy and per-operation authorization",
            ],
        },
        "limits": [
            "case generation only; use protocol_replay_runner.py for authorized execution",
            "do not run destructive mutations against production data",
            "batch review must stay low-count and synthetic",
        ],
    }


def print_markdown(payload: dict[str, Any]) -> None:
    print("# Wuyun GraphQL Test Plan")
    print()
    print(f"- Endpoint: `{payload['url']}`")
    print(f"- Probes: `{len(payload['probes'])}`")
    print("## Checks")
    for item in payload["review_plan"]["checks"]:
        print(f"- {item}")
    print("## Replay Case Preview")
    for probe in payload["probes"]:
        print(f"- `{probe['label']}`")
    print("## Limits")
    for item in payload["limits"]:
        print(f"- {item}")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Generate GraphQL review/replay case plan.")
    parser.add_argument("--url", required=True, help="authorized GraphQL endpoint")
    parser.add_argument("--query", help="baseline safe query")
    parser.add_argument("--operations", help="local .graphql/source file to inventory")
    parser.add_argument("--include-mutation-smoke", action="store_true")
    parser.add_argument("--include-batch-review", action="store_true")
    parser.add_argument("--output", help="write protocol_replay_runner-compatible case JSON")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        payload = build_case(args)
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.output:
        case = {key: payload[key] for key in ["type", "url", "headers", "baseline", "probes"]}
        Path(args.output).write_text(json.dumps(case, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print_markdown(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
