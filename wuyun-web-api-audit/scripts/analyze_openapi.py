#!/usr/bin/env python3
"""Passive OpenAPI/Swagger security lead analyzer.

Reads JSON or YAML specs locally and highlights operations/parameters that merit
manual authorization and validation review. It never contacts endpoints.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head", "trace"}
SENSITIVE_PARAM = re.compile(r"(?i)^(id|.*id|user|userId|account|accountId|tenant|tenantId|org|orgId|owner|ownerId|role|isAdmin|admin|status|state|price|amount|balance|discount|url|uri|redirect|callback|webhook|file|path|key|bucket|object)$")
SENSITIVE_PATH = re.compile(r"(?i)admin|internal|debug|export|import|upload|download|delete|role|permission|tenant|account|webhook|callback|redirect|url|file|path")
MUTATING = {"post", "put", "patch", "delete"}


@dataclass
class OperationLead:
    method: str
    path: str
    issue: str
    priority: str
    evidence: str


def load_spec(path: Path) -> Any:
    text = path.read_text(encoding="utf-8", errors="replace")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    try:
        import yaml  # type: ignore
    except Exception:
        return parse_yaml_fallback(text)
    return yaml.safe_load(text)


def parse_yaml_fallback(text: str) -> dict[str, Any]:
    """Tiny fallback extracting paths/methods/security from common OpenAPI YAML."""
    root: dict[str, Any] = {"paths": {}}
    in_paths = False
    current_path: str | None = None
    current_method: str | None = None
    for raw in text.splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        indent = len(line) - len(line.lstrip())
        if stripped == "paths:":
            in_paths = True
            continue
        if not in_paths:
            if stripped.startswith("security:"):
                root["security"] = [{}]
            continue
        if indent <= 0 and not stripped.startswith("/"):
            in_paths = False
            current_path = None
            current_method = None
            continue
        if indent == 2 and stripped.startswith("/") and stripped.endswith(":"):
            current_path = stripped[:-1]
            root["paths"].setdefault(current_path, {})
            current_method = None
            continue
        if current_path and indent == 4 and stripped[:-1].lower() in HTTP_METHODS:
            current_method = stripped[:-1].lower()
            root["paths"][current_path].setdefault(current_method, {})
            continue
        if current_path and current_method and "security:" in stripped:
            root["paths"][current_path][current_method]["security"] = [{}] if stripped != "security: []" else []
    return root


def schema_fields(schema: Any, prefix: str = "") -> list[str]:
    fields: list[str] = []
    if not isinstance(schema, dict):
        return fields
    props = schema.get("properties")
    if isinstance(props, dict):
        for name, child in props.items():
            full = f"{prefix}.{name}" if prefix else str(name)
            fields.append(full)
            fields.extend(schema_fields(child, full))
    for key in ("items", "allOf", "anyOf", "oneOf"):
        value = schema.get(key)
        if isinstance(value, dict):
            fields.extend(schema_fields(value, prefix))
        elif isinstance(value, list):
            for item in value:
                fields.extend(schema_fields(item, prefix))
    return fields


def param_names(params: Any) -> list[str]:
    names: list[str] = []
    if isinstance(params, list):
        for param in params:
            if isinstance(param, dict) and "name" in param:
                location = param.get("in", "?")
                names.append(f"{param['name']}({location})")
    return names


def request_body_fields(op: dict[str, Any]) -> list[str]:
    rb = op.get("requestBody")
    if not isinstance(rb, dict):
        return []
    content = rb.get("content")
    if not isinstance(content, dict):
        return []
    fields: list[str] = []
    for media in content.values():
        if isinstance(media, dict):
            fields.extend(schema_fields(media.get("schema")))
    return fields


def analyze(spec: Any) -> list[OperationLead]:
    leads: list[OperationLead] = []
    if not isinstance(spec, dict):
        return leads
    paths = spec.get("paths") or {}
    global_security = spec.get("security")
    if not isinstance(paths, dict):
        return leads
    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        path_params = param_names(path_item.get("parameters"))
        for method, op in path_item.items():
            if method.lower() not in HTTP_METHODS or not isinstance(op, dict):
                continue
            m = method.lower()
            op_security = op.get("security", None)
            if op_security == []:
                leads.append(OperationLead(m.upper(), path, "explicitly unauthenticated operation", "high" if m in MUTATING else "medium", "security: []"))
            elif op_security is None and not global_security:
                leads.append(OperationLead(m.upper(), path, "no operation/global security requirement found", "high" if m in MUTATING else "medium", "missing security"))
            if m in MUTATING and SENSITIVE_PATH.search(path):
                leads.append(OperationLead(m.upper(), path, "mutating sensitive-looking endpoint", "high", path))
            elif SENSITIVE_PATH.search(path):
                leads.append(OperationLead(m.upper(), path, "sensitive-looking endpoint path", "medium", path))
            names = path_params + param_names(op.get("parameters"))
            fields = request_body_fields(op)
            risky = [name for name in names + fields if SENSITIVE_PARAM.search(name.split("(")[0].split(".")[-1])]
            if risky:
                priority = "high" if m in MUTATING and any(re.search(r"(?i)role|admin|tenant|owner|price|amount|balance|status|state", x) for x in risky) else "medium"
                leads.append(OperationLead(m.upper(), path, "sensitive parameter/schema field", priority, ", ".join(risky[:12])))
    return dedupe(leads)


def dedupe(leads: list[OperationLead]) -> list[OperationLead]:
    seen = set()
    out = []
    for lead in leads:
        key = (lead.method, lead.path, lead.issue, lead.evidence)
        if key not in seen:
            seen.add(key)
            out.append(lead)
    return out


def print_markdown(leads: list[OperationLead]) -> None:
    print("# OpenAPI Security Lead Analysis")
    print()
    print(f"- Leads: `{len(leads)}`")
    print("- Execution: local spec parsing only")
    print()
    if not leads:
        print("No configured OpenAPI leads found. This is not proof of safe runtime behavior.")
        return
    print("| Priority | Method | Path | Issue | Evidence |")
    print("|---|---|---|---|---|")
    for lead in sorted(leads, key=lambda x: (x.priority != "high", x.priority != "medium", x.path, x.method)):
        print(f"| {lead.priority} | `{lead.method}` | `{lead.path}` | {lead.issue} | `{lead.evidence}` |")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Analyze OpenAPI/Swagger specs for Web/API security leads.")
    parser.add_argument("path", help="OpenAPI JSON/YAML file")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    args = parser.parse_args(argv)
    path = Path(args.path)
    if not path.exists():
        print(f"error: file does not exist: {path}", file=sys.stderr)
        return 2
    try:
        leads = analyze(load_spec(path))
    except Exception as exc:
        print(f"error: failed to parse {path}: {exc}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps({"leads": [asdict(lead) for lead in leads]}, ensure_ascii=False, indent=2))
    else:
        print_markdown(leads)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
