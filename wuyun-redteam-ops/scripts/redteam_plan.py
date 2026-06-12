#!/usr/bin/env python3
"""Generate a local-only authorized red-team/purple-team plan.

The output is a planning artifact. It does not scan targets, generate malware,
collect credentials, bypass controls, or execute payloads.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any

PROFILES: dict[str, dict[str, Any]] = {
    "web": {
        "tactics": ["attack-surface mapping", "authz boundary validation", "input-handling review"],
        "skills": ["$wuyun-web-api-audit", "$wuyun-js-reverse", "$wuyun-exploit-assist"],
        "paths": [
            ("web-api-tenant-boundary", "API object ownership or role checks may be inconsistent", "Use owner-provided test accounts and compare metadata-only authorization outcomes."),
            ("web-input-to-parser", "User input may cross parser/template/query boundaries", "Use inert canary/arithmetic markers and stop before data access or destructive effects."),
        ],
    },
    "cloud": {
        "tactics": ["cloud exposure triage", "metadata boundary review", "temporary credential impact analysis"],
        "skills": ["$wuyun-cloud-vuln", "$wuyun-web-api-audit"],
        "paths": [
            ("cloud-ssrf-metadata", "Server-side fetch features may reach cloud metadata or internal control planes", "Use owner-approved callback/metadata-safe probes and redact credential-shaped values."),
            ("object-storage-exposure", "Object storage or signed URL controls may expose unintended metadata", "Check bucket/listing policy shape and synthetic object access only."),
        ],
    },
    "identity": {
        "tactics": ["session and token review", "federation flow review", "tenant authorization review"],
        "skills": ["$wuyun-auth-audit", "$wuyun-web-api-audit"],
        "paths": [
            ("identity-jwt-claims", "JWT claims or key selection may influence privilege decisions", "Run offline token-structure review and validate only with owner-provided test roles."),
            ("identity-redirect-state", "OAuth/OIDC/SAML state or redirect validation may be inconsistent", "Use synthetic redirect/state cases in a test tenant or owner-assisted logs."),
        ],
    },
    "ai": {
        "tactics": ["prompt boundary mapping", "RAG trust review", "agent tool abuse analysis"],
        "skills": ["$wuyun-ai-audit", "$wuyun-web-api-audit"],
        "paths": [
            ("ai-tool-boundary", "Model-mediated tools may trust untrusted content", "Use benign canary instructions and verify tool authorization boundaries without secrets."),
            ("rag-poisoning-window", "Retrieval content may cross policy or output-sink boundaries", "Use owner-approved synthetic documents and canary-only observations."),
        ],
    },
    "internal": {
        "tactics": ["admin surface review", "CI/CD and config exposure", "dependency and secrets hygiene"],
        "skills": ["$wuyun", "$wuyun-recon", "$wuyun-auth-audit"],
        "paths": [
            ("internal-admin-surface", "Admin or debug interfaces may lack environment isolation", "Inventory local/source routes and validate with owner-provided low-privilege accounts."),
            ("internal-ci-config", "CI/CD configuration may expose secrets or excessive trust", "Review local configs and redact all secret-shaped values."),
        ],
    },
    "ctf": {
        "tactics": ["challenge recon", "hypothesis testing", "artifact recovery"],
        "skills": ["$wuyun", "$wuyun-protocol-analysis", "$wuyun-js-reverse"],
        "paths": [
            ("ctf-service-path", "Challenge service may expose intended vulnerable branch", "Enumerate bounded challenge surface and extract only the intended flag/artifact."),
            ("ctf-protocol-state", "Protocol state transitions may reveal the intended solution", "Model message flow and replay minimal challenge-scoped cases."),
        ],
    },
}

GUARDRAILS = [
    "Confirm user-declared scope, timebox, allowed techniques, contacts, and stop conditions before active testing.",
    "Prefer passive/local/dry-run/canary validation and owner-assisted evidence over invasive proof.",
    "Do not create malware, persistence, stealth automation, credential theft, destructive payloads, data dumping, CAPTCHA automation, proxy rotation, or WAF bypass payload packs.",
    "Redact secrets, tokens, credentials, private data, and unrelated business data by default.",
]

PHASES = [
    ("0-scope-and-roe", "Confirm authorization, scope, excluded assets, rate limits, and stop conditions."),
    ("1-passive-map", "Build asset inventory, roles, trust boundaries, data stores, and telemetry points from local artifacts and low-impact sources."),
    ("2-hypotheses", "Generate multiple falsifiable attack-path hypotheses and rank by evidence, impact, and validation safety."),
    ("3-safe-validation", "Run the smallest safe checks: local proof, dry-run request, metadata-only observation, canary, or synthetic account."),
    ("4-detection-and-response", "Record logs, alerts, coverage gaps, and purple-team improvements for each validated path."),
    ("5-remediation-and-retest", "Assign owners, fixes, regression tests, and retest criteria."),
]


def normalize_profiles(values: list[str]) -> list[str]:
    profiles = values or ["web"]
    if "full" in profiles:
        return ["web", "cloud", "identity", "ai", "internal"]
    return profiles


def build_plan(args: argparse.Namespace) -> dict[str, Any]:
    profiles = normalize_profiles(args.profile)
    profile_data = [PROFILES[item] for item in profiles]
    objectives = args.objective or ["validate high-value attack paths with low-impact evidence"]
    assets = args.asset or ["<scope-to-confirm>"]
    constraints = args.constraint or []

    attack_paths: list[dict[str, Any]] = []
    for profile in profiles:
        for path_id, hypothesis, safe_validation in PROFILES[profile]["paths"]:
            attack_paths.append(
                {
                    "path_id": path_id,
                    "profile": profile,
                    "hypothesis": hypothesis,
                    "safe_validation": safe_validation,
                    "next_skills": PROFILES[profile]["skills"],
                    "confidence": "speculative until tied to concrete artifacts",
                    "blocked_actions": [
                        "do not access unrelated data",
                        "do not use persistence, stealth, malware, or destructive payloads",
                        "do not brute force credentials or bypass human challenges",
                    ],
                }
            )

    handoffs = sorted({skill for item in profile_data for skill in item["skills"]})
    tactics = sorted({tactic for item in profile_data for tactic in item["tactics"]})
    return {
        "status": "plan-only",
        "engagement": args.engagement_name,
        "timebox": args.timebox,
        "profiles": profiles,
        "objectives": objectives,
        "assets": assets,
        "assumptions": args.assumption or [],
        "constraints": constraints,
        "guardrails": GUARDRAILS,
        "tactics": tactics,
        "phases": [
            {
                "phase": phase,
                "objective": objective,
                "evidence_checkpoint": "record exact artifact/request/log reference and confidence before advancing",
            }
            for phase, objective in PHASES
        ],
        "attack_paths": attack_paths,
        "handoffs": handoffs,
        "output_expectations": [
            "asset inventory",
            "attack-path matrix with confidence",
            "evidence ledger",
            "detection opportunities",
            "remediation and retest plan",
            "lessons learned without secrets",
        ],
    }


def print_markdown(plan: dict[str, Any]) -> None:
    print("# Wuyun Red Team / Purple Team Plan")
    print()
    print(f"- Status: `{plan['status']}`")
    print(f"- Engagement: `{plan['engagement']}`")
    print(f"- Profiles: `{', '.join(plan['profiles'])}`")
    print(f"- Assets: `{', '.join(plan['assets'])}`")
    print()
    print("## Guardrails")
    for item in plan["guardrails"]:
        print(f"- {item}")
    print()
    print("## Phases")
    for phase in plan["phases"]:
        print(f"- `{phase['phase']}`: {phase['objective']}")
    print()
    print("## Attack Paths")
    for path in plan["attack_paths"]:
        print(f"- `{path['path_id']}` ({path['profile']}): {path['hypothesis']}")
        print(f"  - Safe validation: {path['safe_validation']}")
        print(f"  - Next skills: {', '.join(path['next_skills'])}")
    print()
    print("## Handoffs")
    for skill in plan["handoffs"]:
        print(f"- {skill}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate a safe authorized red-team/purple-team operation plan.")
    parser.add_argument("--profile", action="append", choices=[*PROFILES.keys(), "full"], default=[], help="operation profile; repeatable")
    parser.add_argument("--objective", action="append", default=[], help="engagement objective; repeatable")
    parser.add_argument("--asset", action="append", default=[], help="in-scope asset or environment; repeatable")
    parser.add_argument("--constraint", action="append", default=[], help="rule-of-engagement constraint; repeatable")
    parser.add_argument("--assumption", action="append", default=[], help="known assumption; repeatable")
    parser.add_argument("--engagement-name", default="authorized-redteam", help="short engagement label")
    parser.add_argument("--timebox", default="owner-defined", help="planned timebox/window")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    return parser


def main(argv: list[str]) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    plan = build_plan(args)
    if args.json:
        print(json.dumps(plan, ensure_ascii=False, indent=2))
    else:
        print_markdown(plan)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
