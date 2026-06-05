#!/usr/bin/env python3
"""Offline cloud IAM/RAM/CAM policy impact triage.

Despite the historical filename, this script handles common action formats from
Aliyun RAM, AWS IAM, Tencent CAM, and similar cloud policy JSON. It never calls
cloud APIs and never needs real credentials.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable

ACTION_RE = re.compile(r"\b([a-zA-Z0-9-]+):([a-zA-Z0-9*._-]+)(?=[\"'\s,\]}]|$)")

CATEGORY_BY_SERVICE = {
    "object-storage": {"oss", "s3", "cos", "obs", "storage"},
    "compute": {"ecs", "ec2", "cvm", "compute", "autoscaling", "as"},
    "database": {"rds", "cdb", "dts", "redis", "mongodb", "polardb", "db"},
    "identity": {"ram", "iam", "cam", "sts"},
    "secrets-kms": {"kms", "secretsmanager", "secretmanager", "ssm", "kmskms"},
    "logging-monitoring": {"actiontrail", "cloudtrail", "sls", "cls", "cloudwatch", "monitor"},
    "network": {"vpc", "slb", "elb", "clb", "nat", "ga", "cdn"},
    "container": {"cs", "ack", "tke", "eks", "k8s", "ccs"},
}

HIGH_PREFIXES = (
    "delete",
    "put",
    "create",
    "update",
    "modify",
    "attach",
    "detach",
    "assume",
    "passrole",
    "run",
    "start",
    "stop",
    "terminate",
    "decrypt",
    "set",
    "write",
    "admin",
    "all",
)
SENSITIVE_READ_PREFIXES = ("getobject", "getsecret", "getcredential", "getpassword", "export", "download", "backup", "snapshot", "query", "select")
READ_PREFIXES = ("list", "describe", "get", "read", "query", "select")


@dataclass
class ActionFinding:
    action: str
    service: str
    operation: str
    category: str
    risk: str
    reason: str


def load_text(paths: list[str]) -> str:
    if not paths:
        return sys.stdin.read()
    parts = []
    for raw in paths:
        path = Path(raw)
        try:
            parts.append(path.read_text(encoding="utf-8", errors="replace"))
        except OSError as exc:
            print(f"warning: could not read {path}: {exc}", file=sys.stderr)
    return "\n".join(parts)


def iter_values(obj: Any) -> Iterable[Any]:
    if isinstance(obj, dict):
        for value in obj.values():
            yield from iter_values(value)
    elif isinstance(obj, list):
        for item in obj:
            yield from iter_values(item)
    else:
        yield obj


def extract_actions(text: str) -> list[str]:
    actions: set[str] = set()
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        obj = None
    if obj is not None:
        for value in iter_values(obj):
            if isinstance(value, str):
                for service, op in ACTION_RE.findall(value):
                    actions.add(f"{service}:{op}")
    for service, op in ACTION_RE.findall(text):
        actions.add(f"{service}:{op}")
    return sorted(actions, key=str.lower)


def category_for(service: str) -> str:
    s = service.lower()
    for category, services in CATEGORY_BY_SERVICE.items():
        if s in services:
            return category
    return "other"


def classify(action: str) -> ActionFinding:
    service, operation = action.split(":", 1)
    category = category_for(service)
    op = operation.lower()
    if operation == "*" or op.endswith("*") or op.startswith(HIGH_PREFIXES):
        risk = "high"
        reason = "write/admin/wildcard-like action"
    elif category in {"object-storage", "database", "identity", "secrets-kms"} and op.startswith(SENSITIVE_READ_PREFIXES):
        risk = "high"
        reason = "sensitive read action in high-value service"
    elif op.startswith(READ_PREFIXES):
        risk = "medium"
        reason = "read/list action may expose infrastructure metadata"
    else:
        risk = "review"
        reason = "unclassified action; review provider semantics"
    return ActionFinding(action, service, operation, category, risk, reason)


def overall(findings: list[ActionFinding]) -> str:
    risks = {f.risk for f in findings}
    if "high" in risks:
        return "high"
    if "medium" in risks:
        return "medium"
    if findings:
        return "review"
    return "none"


def print_markdown(findings: list[ActionFinding]) -> None:
    print("# Cloud Policy Impact Triage")
    print()
    print(f"- Actions found: `{len(findings)}`")
    print(f"- Overall inferred impact: `{overall(findings)}`")
    print("- Cloud API calls: `not performed`")
    print()
    if not findings:
        print("No action strings were found. Provide a RAM/IAM/CAM policy document or action list for offline impact triage.")
        return
    counts = Counter(f.category for f in findings)
    print("## Categories")
    for category, count in counts.most_common():
        print(f"- {category}: {count}")
    print()
    print("## Actions")
    print("| Risk | Category | Action | Reason |")
    print("|---|---|---|---|")
    for item in sorted(findings, key=lambda f: (f.risk != "high", f.risk != "medium", f.category, f.action.lower())):
        print(f"| {item.risk} | {item.category} | `{item.action}` | {item.reason} |")
    print()
    print("## Safe Reporting Note")
    print("Use this as offline impact inference only. Do not use exposed credentials to enumerate resources in production-like scope.")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Offline impact triage for cloud IAM/RAM/CAM policy actions.")
    parser.add_argument("paths", nargs="*", help="policy JSON/text files; stdin is used when omitted")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    args = parser.parse_args(argv)

    actions = extract_actions(load_text(args.paths))
    findings = [classify(action) for action in actions]
    if args.json:
        by_category: dict[str, list[dict]] = defaultdict(list)
        for item in findings:
            by_category[item.category].append(asdict(item))
        print(json.dumps({"overall": overall(findings), "actions": [asdict(f) for f in findings], "by_category": by_category}, ensure_ascii=False, indent=2))
    else:
        print_markdown(findings)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
