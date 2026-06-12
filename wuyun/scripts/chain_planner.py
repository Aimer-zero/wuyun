#!/usr/bin/env python3
"""Build a cross-skill Wuyun chain plan from local evidence artifacts.

This helper does not exploit targets or generate bypass payloads. It converts
local recon/audit/runtime artifacts into a prioritized, evidence-driven plan:
which companion skill to use next, what the likely chain hypothesis is, and how
to validate safely.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


RULES: list[dict[str, Any]] = [
    {
        "stage": "recon",
        "skill": "$wuyun-recon",
        "patterns": [r"\bsubdomain\b", r"\bcrt\.sh\b", r"\broute\b", r"\bwordlist\b", r"\bopenapi\b", r"\bswagger\b"],
        "next_step": "Normalize scoped assets and feed routes/specs into Web/API, auth, and protocol review.",
    },
    {
        "stage": "web-api",
        "skill": "$wuyun-web-api-audit",
        "patterns": [r"\bidor\b", r"\bbola\b", r"\bbfla\b", r"\bssrf\b", r"\bsqli\b", r"\binjection\b", r"\bupload\b", r"/api/"],
        "next_step": "Generate endpoint hypotheses, run dry-run IDOR/BOLA cases, then validate one variable at a time only with authorization.",
    },
    {
        "stage": "exploit-assist",
        "skill": "$wuyun-exploit-assist",
        "patterns": [r"\bpoc\b", r"\breproducer\b", r"\bcanary\b", r"\bdeserialization\b", r"\bssti\b", r"\bxxe\b", r"\bsqli\b"],
        "next_step": "If a lead is already evidenced, build a canary-safe minimal PoC plan with clear stop conditions and no webshells, reverse shells, data dumping, or bypass packs.",
    },
    {
        "stage": "auth",
        "skill": "$wuyun-auth-audit",
        "patterns": [r"\bjwt\b", r"\boauth\b", r"\boidc\b", r"\bsaml\b", r"\bsession\b", r"\bcookie\b", r"\bcsrf\b", r"\btenant\b", r"\brole\b"],
        "next_step": "Trace identity, role, tenant, and session boundaries before treating API differences as impact.",
    },
    {
        "stage": "js-reverse",
        "skill": "$wuyun-js-reverse",
        "patterns": [r"\bbundle\b", r"\bsourcemap\b", r"\bfetch\b", r"\bwebcrypto\b", r"\bcryptojs\b", r"\bsignature\b", r"\bwebpack\b"],
        "next_step": "Extract client-side endpoints, token handling, signing hints, sourcemaps, and runtime-only request behavior.",
    },
    {
        "stage": "protocol",
        "skill": "$wuyun-protocol-analysis",
        "patterns": [r"\bwebsocket\b", r"\bsocket\.io\b", r"\bgraphql\b", r"\bjson-rpc\b", r"\bgrpc\b", r"\bprotobuf\b", r"\bsse\b"],
        "next_step": "Model state machines, subscriptions, channel joins, and object authorization using passive captures first.",
    },
    {
        "stage": "cloud",
        "skill": "$wuyun-cloud-vuln",
        "patterns": [r"\baws\b", r"\baliyun\b", r"\btencent\b", r"\bsts\b", r"\bmetadata\b", r"\bimds\b", r"\bbucket\b", r"\biam\b"],
        "next_step": "Use cloud-specific offline/owner-assisted triage for temporary credentials, object storage, and IAM impact.",
    },
    {
        "stage": "runtime",
        "skill": "$wuyun-browser-runtime",
        "patterns": [r"\bhar\b", r"\bdevtools\b", r"\bservice worker\b", r"\bcache\b", r"\bcloudflare\b", r"\bwaf\b", r"\bbot\b"],
        "next_step": "Attribute CDN/WAF/risk-control behavior from captures before claiming origin or app behavior.",
    },
    {
        "stage": "evasion-analysis",
        "skill": "$wuyun-evasion",
        "patterns": [r"\bcanonicalization\b", r"\bparser mismatch\b", r"\bnormalization\b", r"\borigin exposure\b", r"\bhpp\b"],
        "next_step": "Use benign markers and owner-assisted plans to evaluate normalization and detection coverage; do not generate bypass payloads.",
    },
    {
        "stage": "ai-security",
        "skill": "$wuyun-ai-audit",
        "patterns": [r"\bprompt injection\b", r"\brag\b", r"\bagent\b", r"\btool call\b", r"\bllm\b", r"\bmodel\b"],
        "next_step": "Map AI inputs, retrieval/tool boundaries, and policy outcomes with benign compliance cases and disallowed-control cases.",
    },
]


@dataclass
class Signal:
    stage: str
    skill: str
    evidence_file: str
    score: int
    matched_terms: list[str]
    next_step: str


def stringify_json(value: Any) -> str:
    if isinstance(value, dict):
        return " ".join([str(k) + " " + stringify_json(v) for k, v in value.items()])
    if isinstance(value, list):
        return " ".join(stringify_json(item) for item in value)
    return str(value)


def read_artifact(path: Path) -> str:
    text = path.read_text(encoding="utf-8", errors="replace")
    try:
        return stringify_json(json.loads(text))
    except json.JSONDecodeError:
        return text


def collect_signals(paths: list[Path]) -> list[Signal]:
    signals: list[Signal] = []
    for path in paths:
        text = read_artifact(path).lower()
        rel = str(path)
        for rule in RULES:
            matched: list[str] = []
            for pattern in rule["patterns"]:
                if re.search(pattern, text, re.IGNORECASE):
                    matched.append(pattern)
            if matched:
                signals.append(
                    Signal(
                        stage=rule["stage"],
                        skill=rule["skill"],
                        evidence_file=rel,
                        score=len(matched),
                        matched_terms=matched,
                        next_step=rule["next_step"],
                    )
                )
    return sorted(signals, key=lambda item: (-item.score, item.stage, item.evidence_file))


def confidence(score: int) -> str:
    if score >= 4:
        return "medium"
    if score >= 2:
        return "low-medium"
    return "low"


def build_chain(signals: list[Signal]) -> list[dict[str, Any]]:
    by_stage: dict[str, list[Signal]] = {}
    for signal in signals:
        by_stage.setdefault(signal.stage, []).append(signal)

    order = ["recon", "js-reverse", "runtime", "web-api", "auth", "protocol", "cloud", "exploit-assist", "evasion-analysis", "ai-security"]
    nodes = []
    for stage in order:
        rows = by_stage.get(stage)
        if not rows:
            continue
        top = rows[0]
        nodes.append(
            {
                "stage": stage,
                "recommended_skill": top.skill,
                "confidence": confidence(sum(row.score for row in rows)),
                "evidence_files": sorted({row.evidence_file for row in rows}),
                "matched_terms": sorted({term for row in rows for term in row.matched_terms}),
                "next_step": top.next_step,
            }
        )
    return nodes


def build_hypotheses(nodes: list[dict[str, Any]]) -> list[str]:
    stages = {node["stage"] for node in nodes}
    matched_text = " ".join(term for node in nodes for term in node["matched_terms"])
    hypotheses: list[str] = []
    if {"recon", "js-reverse", "web-api"} & stages and "auth" in stages:
        hypotheses.append("Client/API inventory plus auth signals may indicate object or function authorization review should be prioritized.")
    if "runtime" in stages and "evasion-analysis" in stages:
        hypotheses.append("Observed CDN/WAF/runtime behavior should be attributed before treating response differences as application vulnerabilities.")
    if "protocol" in stages and "auth" in stages:
        hypotheses.append("Protocol state transitions may need role or tenant boundary checks on channel join, subscription, or mutation actions.")
    if "cloud" in stages and "ssrf" in matched_text.lower():
        hypotheses.append("Cloud exposure signals should be triaged with metadata/STS impact boundaries and no data extraction.")
    if "exploit-assist" in stages:
        hypotheses.append("Confirmed leads should become canary-safe PoC plans with explicit stop conditions, cleanup, and no persistent or data-dumping payloads.")
    if "ai-security" in stages:
        hypotheses.append("AI/RAG/tool surfaces should be tested with benign boundary cases and defensive expected outcomes, not jailbreak bypass libraries.")
    return hypotheses or ["No complete multi-stage chain is evident yet; collect more endpoint, auth, runtime, or source evidence before linking findings."]


def build_payload(paths: list[Path]) -> dict[str, Any]:
    signals = collect_signals(paths)
    nodes = build_chain(signals)
    counts = Counter(signal.stage for signal in signals)
    return {
        "artifacts": [str(path) for path in paths],
        "signal_counts": dict(sorted(counts.items())),
        "signals": [asdict(signal) for signal in signals],
        "chain_nodes": nodes,
        "chain_hypotheses": build_hypotheses(nodes),
        "safe_execution_boundary": [
            "This is planning and evidence synthesis only.",
            "Do not turn evasion-analysis into WAF bypass, stealth fingerprint spoofing, or AI filter bypass execution.",
            "Validate one link at a time with owned accounts, synthetic records, and low-impact tests.",
            "Report confirmed, likely, speculative, ruled-out, and deferred links separately.",
        ],
    }


def print_markdown(payload: dict[str, Any]) -> None:
    print("# Wuyun Chain Planner")
    print()
    print("## Signal Counts")
    if payload["signal_counts"]:
        for stage, count in payload["signal_counts"].items():
            print(f"- `{stage}`: {count}")
    else:
        print("- No chain signals found.")
    print()
    print("## Recommended Chain")
    if payload["chain_nodes"]:
        for index, node in enumerate(payload["chain_nodes"], start=1):
            print(f"{index}. `{node['stage']}` → `{node['recommended_skill']}` confidence `{node['confidence']}`")
            print(f"   Evidence: `{', '.join(node['evidence_files'])}`")
            print(f"   Next: {node['next_step']}")
    else:
        print("- Collect recon, source, runtime, API, auth, protocol, cloud, or AI evidence first.")
    print()
    print("## Chain Hypotheses")
    for item in payload["chain_hypotheses"]:
        print(f"- {item}")
    print()
    print("## Safety Boundary")
    for item in payload["safe_execution_boundary"]:
        print(f"- {item}")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Build a safe cross-skill Wuyun chain plan from local artifacts.")
    parser.add_argument("artifacts", nargs="+", help="local JSON/Markdown/text artifacts from recon/audit/runtime helpers")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    args = parser.parse_args(argv)

    paths = [Path(item).resolve() for item in args.artifacts]
    missing = [str(path) for path in paths if not path.exists()]
    if missing:
        print(f"error: missing artifact(s): {', '.join(missing)}", file=sys.stderr)
        return 2
    payload = build_payload(paths)
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print_markdown(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
