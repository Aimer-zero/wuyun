#!/usr/bin/env python3
"""Map local red-team path artifacts to purple-team detection/remediation coverage.

This helper is local-only. It reads Wuyun redteam-plan / attack-matrix JSON or
plain text artifacts and emits benign detection, telemetry, remediation, and
retest workstreams. It does not generate stealth, bypass, malware, credential
collection, or exploit payloads.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

BLOCKED_ACTIONS = [
    "no stealth, persistence, malware, destructive payloads, or credential theft",
    "no data dumping, unrelated data access, brute force, or CAPTCHA automation",
    "no WAF bypass payload packs, proxy rotation, or request fingerprint spoofing",
]

COVERAGE = {
    "web": {
        "telemetry": [
            "API gateway/access logs with route, principal, tenant/object id, decision, and correlation id",
            "application authorization decision logs for allow/deny and ownership check reason",
            "audit events for role, tenant, account, or object access changes",
        ],
        "detection_objectives": [
            "detect owner-provided cross-tenant test attempts that should fail with 403/404",
            "detect privileged route access from non-privileged test role",
            "detect unusual allow decisions where actor tenant differs from object tenant",
        ],
        "safe_emulation": "Use two owner-provided synthetic tenants/accounts and compare metadata-only status, decision log, and correlation id; do not enumerate real objects.",
        "remediation_tests": [
            "add unit/integration tests for object ownership before controller/service side effects",
            "assert deny-by-default when tenant/object owner is missing, ambiguous, or cross-tenant",
            "add regression fixtures for every role and tenant boundary in the affected route",
        ],
    },
    "cloud": {
        "telemetry": [
            "cloud control-plane audit logs for STS/IAM/CAM role assumptions and denied actions",
            "application egress logs for metadata/link-local/internal host attempts in test environments",
            "object storage access logs for synthetic bucket/object reads and listing attempts",
        ],
        "detection_objectives": [
            "detect owner-approved metadata-safe SSRF canary attempts from application servers",
            "detect temporary credential usage outside expected service, region, or source identity",
            "detect synthetic bucket/listing access that should be denied",
        ],
        "safe_emulation": "Use metadata-safe canaries or owner-assisted logs; redact credential-shaped values and never print live secrets.",
        "remediation_tests": [
            "enforce egress allowlists and block metadata endpoints by default",
            "scope temporary credentials to least privilege and short duration",
            "add storage policy tests for public/list/read/write denial on synthetic objects",
        ],
    },
    "identity": {
        "telemetry": [
            "IdP sign-in, token issuance, token validation, and federation error logs",
            "session lifecycle logs for cookie rotation, fixation, logout, and privilege change",
            "application auth middleware logs with claim, scope, role, tenant, and key id metadata",
        ],
        "detection_objectives": [
            "detect invalid or unexpected JWT alg/kid/claim-shape in offline or test-tenant validation",
            "detect redirect/state/nonce mismatch attempts in owner-approved test flows",
            "detect tenant or role claim mismatch at authorization decision points",
        ],
        "safe_emulation": "Use offline token structure review and owner-provided test roles; do not brute force tokens or collect credentials.",
        "remediation_tests": [
            "pin accepted algorithms and key ids, reject path-like or attacker-controlled key selectors",
            "add redirect_uri/state/nonce regression tests for every OAuth/OIDC/SAML client",
            "centralize tenant/role authorization checks after token validation",
        ],
    },
    "protocol": {
        "telemetry": [
            "WebSocket/RPC gateway logs with connection id, principal, operation, and close reason",
            "GraphQL operation logs with operationName, variables shape, auth decision, and complexity",
            "replay-window/signature verification logs with nonce/timestamp decision metadata",
        ],
        "detection_objectives": [
            "detect synthetic replay attempts outside owner-approved nonce/timestamp windows",
            "detect unauthorized GraphQL/RPC operations by role or tenant",
            "detect protocol state transitions that skip expected authentication or sequencing",
        ],
        "safe_emulation": "Recover request shapes from local artifacts first; replay only owner-approved synthetic operations with low rate and explicit scope.",
        "remediation_tests": [
            "bind signatures to method, path, body hash, nonce, timestamp, role, and tenant where applicable",
            "add state-machine tests for authentication and authorization before sensitive messages",
            "add GraphQL/RPC allowlist and complexity regression tests",
        ],
    },
    "ai": {
        "telemetry": [
            "LLM prompt, retrieval, and tool-call audit logs with canary-safe redaction",
            "agent authorization logs for tool name, user, input schema, and approval decision",
            "RAG document ids, source trust labels, and output-sink routing decisions",
        ],
        "detection_objectives": [
            "detect benign canary prompt injection reaching a tool boundary",
            "detect retrieval from untrusted or cross-tenant synthetic documents",
            "detect model output routed to sensitive sinks without policy approval",
        ],
        "safe_emulation": "Use owner-approved synthetic documents and benign canary instructions only; never request or reveal secrets.",
        "remediation_tests": [
            "enforce tool allowlists, explicit user authorization, and schema validation before tool execution",
            "label and isolate retrieval corpora by tenant/source trust",
            "add output-sink policy checks and regression tests for indirect prompt injection",
        ],
    },
    "waf": {
        "telemetry": [
            "CDN/WAF events with Ray/request id, rule id, action, host, path, and managed challenge state",
            "origin access logs correlated to CDN Ray/request id",
            "browser/HAR evidence for challenge, Turnstile, rate-limit, and bot-defense attribution",
        ],
        "detection_objectives": [
            "distinguish WAF/CDN challenge behavior from origin authorization behavior",
            "detect repeated owner-approved canary requests that trigger managed rules",
            "detect origin exposure drift only through passive owner-assisted evidence",
        ],
        "safe_emulation": "Preserve Ray IDs and owner-assisted logs; do not automate CAPTCHA, spoof fingerprints, rotate proxies, or generate bypass payload packs.",
        "remediation_tests": [
            "document rule ownership and expected action for protected routes",
            "add origin allowlist and direct-origin exposure checks in owner-controlled infrastructure",
            "add regression runbooks for false-positive and expected-challenge triage",
        ],
    },
    "internal": {
        "telemetry": [
            "admin action audit logs with actor, role, target, and change reason",
            "CI/CD job, secret access, deployment, and artifact publication logs",
            "configuration change and dependency update logs",
        ],
        "detection_objectives": [
            "detect low-privilege synthetic access to admin/debug surfaces",
            "detect secret-shaped values in CI logs/artifacts before publication",
            "detect unexpected deployment or config-change attempts in test pipelines",
        ],
        "safe_emulation": "Use local/source review and owner-provided low-privilege test accounts; do not access production secrets or modify live jobs.",
        "remediation_tests": [
            "gate admin/debug routes behind centralized authz and environment checks",
            "redact and block secret-shaped values in CI logs/artifacts",
            "add least-privilege tests for CI tokens and deployment roles",
        ],
    },
    "ctf": {
        "telemetry": [
            "challenge service logs or local trace output scoped to the lab instance",
            "input/output transcripts needed to replay the intended challenge solution",
            "artifact hashes and offsets for binary/protocol/source evidence",
        ],
        "detection_objectives": [
            "record exact solved path and ruled-out alternatives for learning",
            "identify intended vulnerable branch without touching unrelated services",
            "preserve replayable minimal exploit transcript for the lab only",
        ],
        "safe_emulation": "Keep actions inside the challenge scope and extract only the intended artifact/flag.",
        "remediation_tests": [
            "write lesson notes for the pattern and false-positive reducers",
            "capture minimal reproduction commands and cleanup steps",
            "separate lab-only exploit mechanics from production-safe guidance",
        ],
    },
}

SIGNAL_TO_CATEGORY = {
    "web-api-authz": "web",
    "identity-token": "identity",
    "cloud-boundary": "cloud",
    "js-runtime-protocol": "protocol",
    "ai-agent-boundary": "ai",
    "waf-risk-control": "waf",
}

PROFILE_TO_CATEGORY = {
    "web": "web",
    "cloud": "cloud",
    "identity": "identity",
    "ai": "ai",
    "internal": "internal",
    "ctf": "ctf",
}

KEYWORD_TO_CATEGORY = [
    (re.compile(r"\b(cloudflare|cf-ray|turnstile|waf|captcha|managed challenge)\b", re.I), "waf"),
    (re.compile(r"\b(jwt|oauth|oidc|saml|cookie|session|redirect_uri|nonce)\b", re.I), "identity"),
    (re.compile(r"\b(metadata|sts|iam|cam|bucket|s3|oss|cos|169\.254\.169\.254)\b", re.I), "cloud"),
    (re.compile(r"\b(websocket|graphql|json-rpc|socket\.io|grpc|nonce|signature)\b", re.I), "protocol"),
    (re.compile(r"\b(llm|prompt|rag|agent|tool_call|function_call|embedding)\b", re.I), "ai"),
    (re.compile(r"\b(admin|ci/cd|pipeline|debug|deployment|secret)\b", re.I), "internal"),
    (re.compile(r"\b(userId|tenantId|accountId|orgId|api/|route|endpoint)\b", re.I), "web"),
]


def read_artifact(path: Path) -> tuple[str, Any | None]:
    raw = path.read_bytes()[:750_000]
    text = raw.decode("utf-8", errors="replace")
    try:
        return text, json.loads(text)
    except json.JSONDecodeError:
        return text, None


def compact_source(path: Path) -> str:
    return path.name


def categories_from_text(text: str) -> list[str]:
    cats: list[str] = []
    for pattern, category in KEYWORD_TO_CATEGORY:
        if pattern.search(text) and category not in cats:
            cats.append(category)
    return cats


def path_items_from_json(data: Any, source: str) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    if not isinstance(data, dict):
        return items
    if isinstance(data.get("entries"), list):
        for entry in data["entries"]:
            if not isinstance(entry, dict):
                continue
            path_id = str(entry.get("path_id") or entry.get("name") or "artifact-path")
            category = SIGNAL_TO_CATEGORY.get(path_id) or categories_from_text(json.dumps(entry, ensure_ascii=False))[:1]
            items.append(
                {
                    "path_id": path_id,
                    "category": category[0] if isinstance(category, list) and category else category or "web",
                    "source": source,
                    "surface": entry.get("surface") or entry.get("tactic") or "artifact-derived surface",
                    "evidence": entry.get("matched_patterns") or entry.get("evidence") or [],
                    "confidence": entry.get("confidence", "low"),
                }
            )
    if isinstance(data.get("attack_paths"), list):
        for entry in data["attack_paths"]:
            if not isinstance(entry, dict):
                continue
            profile = str(entry.get("profile") or "web")
            items.append(
                {
                    "path_id": str(entry.get("path_id") or "planned-path"),
                    "category": PROFILE_TO_CATEGORY.get(profile, "web"),
                    "source": source,
                    "surface": entry.get("hypothesis") or "planned attack path",
                    "evidence": ["plan-only"],
                    "confidence": entry.get("confidence", "speculative"),
                }
            )
    return items


def path_items_from_text(text: str, source: str) -> list[dict[str, Any]]:
    items = []
    for category in categories_from_text(text):
        items.append(
            {
                "path_id": f"{category}-text-signal",
                "category": category,
                "source": source,
                "surface": f"{category} signal from local artifact text",
                "evidence": ["keyword-signal"],
                "confidence": "low",
            }
        )
    return items


def dedupe_items(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str]] = set()
    out = []
    for item in items:
        key = (str(item["path_id"]), str(item["category"]), str(item["source"]))
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def build_workstream(item: dict[str, Any], owners: list[str]) -> dict[str, Any]:
    category = item["category"] if item["category"] in COVERAGE else "web"
    coverage = COVERAGE[category]
    return {
        "path_id": item["path_id"],
        "category": category,
        "source": item["source"],
        "surface": item["surface"],
        "confidence": item["confidence"],
        "evidence": item["evidence"],
        "telemetry_sources": coverage["telemetry"],
        "detection_objectives": coverage["detection_objectives"],
        "safe_emulation": coverage["safe_emulation"],
        "remediation_tests": coverage["remediation_tests"],
        "owner_handoff": owners or ["security", "application-owner", "detection-engineering"],
        "evidence_ledger_fields": [
            "path_id",
            "source_artifact",
            "controlled_input_or_canary",
            "expected_log_or_decision",
            "observed_result",
            "sensitive_data_redaction",
            "owner_confirmation",
            "retest_status",
        ],
        "blocked_actions": BLOCKED_ACTIONS,
    }


def build_mapping(paths: list[Path], owners: list[str], top: int) -> dict[str, Any]:
    items: list[dict[str, Any]] = []
    artifacts = []
    for path in paths:
        text, data = read_artifact(path)
        source = compact_source(path)
        artifacts.append({"path": str(path), "source": source, "bytes_read": min(path.stat().st_size, 750_000)})
        parsed_items = path_items_from_json(data, source) if data is not None else []
        items.extend(parsed_items or path_items_from_text(text, source))
    items = dedupe_items(items)
    if top > 0:
        items = items[:top]
    workstreams = [build_workstream(item, owners) for item in items]
    categories = sorted({item["category"] for item in workstreams})
    return {
        "status": "mapped" if workstreams else "no-signal",
        "artifacts": artifacts,
        "categories": categories,
        "workstreams": workstreams,
        "summary": {
            "workstream_count": len(workstreams),
            "telemetry_source_count": sum(len(item["telemetry_sources"]) for item in workstreams),
            "detection_objective_count": sum(len(item["detection_objectives"]) for item in workstreams),
            "remediation_test_count": sum(len(item["remediation_tests"]) for item in workstreams),
        },
        "guardrails": BLOCKED_ACTIONS,
        "next_step": "Review workstreams with asset owners, then run the smallest safe emulation and capture redacted evidence ledger entries.",
    }


def print_markdown(mapping: dict[str, Any]) -> None:
    print("# Wuyun Purple-Team Coverage Map")
    print()
    print(f"- Status: `{mapping['status']}`")
    print(f"- Workstreams: `{mapping['summary']['workstream_count']}`")
    print(f"- Categories: `{', '.join(mapping['categories']) if mapping['categories'] else 'none'}`")
    print()
    for item in mapping["workstreams"]:
        print(f"## {item['path_id']}")
        print(f"- Category: `{item['category']}`")
        print(f"- Source: `{item['source']}`")
        print(f"- Surface: {item['surface']}")
        print(f"- Safe emulation: {item['safe_emulation']}")
        print("- Telemetry sources:")
        for row in item["telemetry_sources"]:
            print(f"  - {row}")
        print("- Detection objectives:")
        for row in item["detection_objectives"]:
            print(f"  - {row}")
        print("- Remediation tests:")
        for row in item["remediation_tests"]:
            print(f"  - {row}")
        print()
    if not mapping["workstreams"]:
        print("No workstreams mapped. Provide redteam-plan, attack-matrix, recon, HAR, OpenAPI, auth, cloud, AI, or JS artifacts.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Map local red-team artifacts to purple-team detection/remediation workstreams.")
    parser.add_argument("artifacts", nargs="*", help="local redteam-plan, attack-matrix, JSON, HAR, or text artifacts")
    parser.add_argument("--owner", action="append", default=[], help="owner/team handoff label; repeatable")
    parser.add_argument("--top", type=int, default=0, help="limit workstreams")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    return parser


def main(argv: list[str]) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    paths = [Path(item).resolve() for item in args.artifacts]
    missing = [str(path) for path in paths if not path.exists()]
    if missing:
        print(f"error: missing artifact(s): {', '.join(missing)}", file=sys.stderr)
        return 2
    if not paths:
        print("error: provide at least one local artifact", file=sys.stderr)
        return 2
    mapping = build_mapping(paths, args.owner, args.top)
    if args.json:
        print(json.dumps(mapping, ensure_ascii=False, indent=2))
    else:
        print_markdown(mapping)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
