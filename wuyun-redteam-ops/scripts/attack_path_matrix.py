#!/usr/bin/env python3
"""Cluster local artifacts into safe red-team attack-path hypotheses.

This helper reads local text/JSON/HAR-style artifacts only. It never contacts
network targets and never generates bypass, malware, persistence, or credential
collection payloads.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

SIGNALS = [
    {
        "name": "web-api-authz",
        "patterns": [r"\b(userId|tenantId|accountId|orgId)\b", r"\b(openapi|swagger|route|endpoint|api/)\b"],
        "tactic": "Privilege boundary validation",
        "surface": "Web/API object or tenant authorization",
        "next_skill": "$wuyun-web-api-audit",
        "safe_validation": "Use owner-provided test identities and compare metadata-only authorization outcomes; do not enumerate real objects.",
    },
    {
        "name": "identity-token",
        "patterns": [r"\b(jwt|bearer|oauth|oidc|saml|cookie|session)\b", r"\b(role|scope|claim|kid|redirect_uri|state)\b"],
        "tactic": "Identity and session boundary review",
        "surface": "JWT/OAuth/SAML/session handling",
        "next_skill": "$wuyun-auth-audit",
        "safe_validation": "Run offline token/flow structure review and validate only with owner-provided test roles.",
    },
    {
        "name": "cloud-boundary",
        "patterns": [r"\b(metadata|169\.254\.169\.254|sts|iam|cam|bucket|s3|oss|cos)\b", r"\b(accesskey|secretaccesskey|securitytoken|rolearn)\b"],
        "tactic": "Cloud control-plane boundary review",
        "surface": "Cloud SSRF, metadata, temporary credential, or storage exposure",
        "next_skill": "$wuyun-cloud-vuln",
        "safe_validation": "Use metadata-safe probes or owner-assisted cloud logs; redact credential-shaped values.",
    },
    {
        "name": "js-runtime-protocol",
        "patterns": [r"\b(websocket|graphql|json-rpc|socket\.io|sse|grpc)\b", r"\b(fetch|xhr|signature|crypto|nonce|timestamp)\b"],
        "tactic": "Client/runtime protocol analysis",
        "surface": "Frontend signing, WebSocket, GraphQL, or replay-sensitive protocol",
        "next_skill": "$wuyun-js-reverse,$wuyun-protocol-analysis",
        "safe_validation": "Recover request shapes and replay windows from local artifacts before any authorized protocol replay.",
    },
    {
        "name": "ai-agent-boundary",
        "patterns": [r"\b(llm|prompt|rag|embedding|vector|agent|tool_call|function_call)\b", r"\b(system prompt|retrieval|output sink|connector)\b"],
        "tactic": "Model-mediated trust-boundary review",
        "surface": "LLM/RAG/agent tool workflow",
        "next_skill": "$wuyun-ai-audit",
        "safe_validation": "Use benign canary prompts/documents and verify tool authorization without exfiltrating secrets.",
    },
    {
        "name": "waf-risk-control",
        "patterns": [r"\b(cloudflare|cf-ray|turnstile|waf|bot management|captcha)\b", r"\b(403|challenge|managed challenge|rate limit)\b"],
        "tactic": "Defensive control attribution",
        "surface": "CDN/WAF/bot-defense behavior",
        "next_skill": "$wuyun-browser-runtime,$wuyun-evasion",
        "safe_validation": "Preserve Ray IDs and owner-assisted evidence; do not generate bypass payload packs or automate CAPTCHA.",
    },
]

BLOCKED_ACTIONS = [
    "no malware, persistence, stealth automation, or destructive payloads",
    "no credential theft, brute force, data dumping, or unrelated data access",
    "no WAF bypass payload packs, CAPTCHA automation, proxy rotation, or fingerprint spoofing",
]


def read_artifact(path: Path) -> str:
    raw = path.read_bytes()[:750_000]
    return raw.decode("utf-8", errors="replace")


def score_signal(text: str, patterns: list[str]) -> tuple[int, list[str]]:
    hits: list[str] = []
    lower = text.lower()
    for pattern in patterns:
        if re.search(pattern, lower, flags=re.IGNORECASE):
            hits.append(pattern)
    return len(hits), hits


def build_matrix(paths: list[Path], profiles: list[str], top: int) -> dict[str, Any]:
    artifacts: list[dict[str, Any]] = []
    combined = []
    for path in paths:
        text = read_artifact(path)
        artifacts.append({"path": str(path), "bytes_read": min(path.stat().st_size, 750_000)})
        combined.append(text)
    corpus = "\n".join(combined)

    entries = []
    for signal in SIGNALS:
        score, hits = score_signal(corpus, signal["patterns"])
        if score == 0:
            continue
        entries.append(
            {
                "path_id": signal["name"],
                "score": score,
                "tactic": signal["tactic"],
                "surface": signal["surface"],
                "matched_patterns": hits,
                "safe_validation": signal["safe_validation"],
                "next_skill": signal["next_skill"],
                "confidence": "medium" if score >= 2 else "low",
                "blocked_actions": BLOCKED_ACTIONS,
            }
        )
    entries.sort(key=lambda item: (-item["score"], item["path_id"]))
    if top > 0:
        entries = entries[:top]
    return {
        "status": "artifact-clustered" if entries else "no-signal",
        "profiles": profiles,
        "artifacts": artifacts,
        "entries": entries,
        "guardrails": BLOCKED_ACTIONS,
        "next_step": "Route each non-empty entry to the listed Wuyun companion and validate with the smallest safe evidence step.",
    }


def print_markdown(matrix: dict[str, Any]) -> None:
    print("# Wuyun Attack Path Matrix")
    print()
    print(f"- Status: `{matrix['status']}`")
    print(f"- Artifacts: `{len(matrix['artifacts'])}`")
    print()
    for entry in matrix["entries"]:
        print(f"## {entry['path_id']}")
        print(f"- Score: `{entry['score']}`")
        print(f"- Tactic: {entry['tactic']}")
        print(f"- Surface: {entry['surface']}")
        print(f"- Next skill: {entry['next_skill']}")
        print(f"- Safe validation: {entry['safe_validation']}")
        print()
    if not matrix["entries"]:
        print("No strong red-team path signal found in local artifacts. Add recon, HAR, OpenAPI, JS, auth, cloud, or AI audit outputs.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build a safe attack-path matrix from local Wuyun artifacts.")
    parser.add_argument("artifacts", nargs="*", help="local JSON/HAR/text/source artifacts")
    parser.add_argument("--profile", action="append", default=[], help="engagement profile label; repeatable")
    parser.add_argument("--top", type=int, default=0, help="limit entries")
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
    matrix = build_matrix(paths, args.profile or ["mixed"], args.top)
    if args.json:
        print(json.dumps(matrix, ensure_ascii=False, indent=2))
    else:
        print_markdown(matrix)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
