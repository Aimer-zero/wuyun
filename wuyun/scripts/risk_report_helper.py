#!/usr/bin/env python3
"""CVSS/ATT&CK/ATLAS/PoC helper for Wuyun reports."""
from __future__ import annotations

import argparse
import json
from dataclasses import dataclass


CVSS_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PRU": {"N": 0.85, "L": 0.62, "H": 0.27},
    "PRC": {"N": 0.85, "L": 0.68, "H": 0.5},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}
TYPE_MAP = {
    "idor": {"attack": ["T1078 Valid Accounts"], "atlas": [], "default": {"C": "H", "I": "L", "A": "N"}},
    "bola": {"attack": ["T1078 Valid Accounts"], "atlas": [], "default": {"C": "H", "I": "L", "A": "N"}},
    "sqli": {"attack": ["T1190 Exploit Public-Facing Application"], "atlas": [], "default": {"C": "H", "I": "H", "A": "L"}},
    "ssrf": {"attack": ["T1190 Exploit Public-Facing Application"], "atlas": [], "default": {"C": "H", "I": "L", "A": "L"}},
    "xss": {"attack": ["T1189 Drive-by Compromise"], "atlas": [], "default": {"C": "L", "I": "L", "A": "N"}},
    "prompt-injection": {"attack": [], "atlas": ["AML.T0051 Prompt Injection"], "default": {"C": "L", "I": "L", "A": "N"}},
    "rag-poisoning": {"attack": [], "atlas": ["AML.T0058 Data Poisoning"], "default": {"C": "L", "I": "H", "A": "N"}},
    "agent-tool-abuse": {"attack": [], "atlas": ["AML.T0051 Prompt Injection"], "default": {"C": "H", "I": "H", "A": "L"}},
    "auth": {"attack": ["T1078 Valid Accounts"], "atlas": [], "default": {"C": "H", "I": "H", "A": "N"}},
}


def round_up_1(value: float) -> float:
    return int(value * 10 + 0.999999) / 10.0


def cvss_score(vector: dict[str, str]) -> float:
    scope_changed = vector["S"] == "C"
    pr_key = "PRC" if scope_changed else "PRU"
    impact_sub = 1 - ((1 - CVSS_WEIGHTS["CIA"][vector["C"]]) * (1 - CVSS_WEIGHTS["CIA"][vector["I"]]) * (1 - CVSS_WEIGHTS["CIA"][vector["A"]]))
    impact = 7.52 * (impact_sub - 0.029) - 3.25 * ((impact_sub - 0.02) ** 15) if scope_changed else 6.42 * impact_sub
    exploitability = 8.22 * CVSS_WEIGHTS["AV"][vector["AV"]] * CVSS_WEIGHTS["AC"][vector["AC"]] * CVSS_WEIGHTS[pr_key][vector["PR"]] * CVSS_WEIGHTS["UI"][vector["UI"]]
    if impact <= 0:
        return 0.0
    if scope_changed:
        return min(round_up_1(1.08 * (impact + exploitability)), 10.0)
    return min(round_up_1(impact + exploitability), 10.0)


def severity(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "none"


def build(args: argparse.Namespace) -> dict:
    mapping = TYPE_MAP.get(args.type, {"attack": [], "atlas": [], "default": {"C": args.confidentiality, "I": args.integrity, "A": args.availability}})
    defaults = mapping["default"]
    vector = {
        "AV": args.attack_vector,
        "AC": args.attack_complexity,
        "PR": args.privileges_required,
        "UI": args.user_interaction,
        "S": args.scope,
        "C": args.confidentiality or defaults["C"],
        "I": args.integrity or defaults["I"],
        "A": args.availability or defaults["A"],
    }
    score = cvss_score(vector)
    vector_s = "CVSS:3.1/" + "/".join(f"{k}:{v}" for k, v in vector.items())
    return {
        "type": args.type,
        "cvss_vector": vector_s,
        "score": score,
        "severity": severity(score),
        "attack_mapping": mapping["attack"],
        "atlas_mapping": mapping["atlas"],
        "poc_template": {
            "summary": "<one sentence impact>",
            "preconditions": "<role/account/scope required>",
            "request_or_steps": "<minimal reproducible request or safe steps>",
            "expected": "<secure expected result>",
            "actual": "<observed vulnerable result>",
            "evidence": "<paths/request IDs/screenshots>",
            "cleanup": "<temporary artifacts removed or documented>",
        },
        "limits": ["CVSS is a helper estimate; review business context before final severity"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate CVSS/ATT&CK/ATLAS/PoC helper output.")
    parser.add_argument("--type", required=True, choices=sorted(TYPE_MAP))
    parser.add_argument("--attack-vector", choices=["N", "A", "L", "P"], default="N")
    parser.add_argument("--attack-complexity", choices=["L", "H"], default="L")
    parser.add_argument("--privileges-required", choices=["N", "L", "H"], default="L")
    parser.add_argument("--user-interaction", choices=["N", "R"], default="N")
    parser.add_argument("--scope", choices=["U", "C"], default="U")
    parser.add_argument("--confidentiality", choices=["H", "L", "N"])
    parser.add_argument("--integrity", choices=["H", "L", "N"])
    parser.add_argument("--availability", choices=["H", "L", "N"])
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    payload = build(args)
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print("# Wuyun Risk Report Helper")
        print()
        print(f"- Type: `{payload['type']}`")
        print(f"- CVSS: `{payload['cvss_vector']}`")
        print(f"- Score: `{payload['score']}`")
        print(f"- Severity: `{payload['severity']}`")
        print("## ATT&CK")
        for item in payload["attack_mapping"] or ["<none>"]:
            print(f"- {item}")
        print("## ATLAS")
        for item in payload["atlas_mapping"] or ["<none>"]:
            print(f"- {item}")
        print("## PoC Template")
        for key, value in payload["poc_template"].items():
            print(f"- {key}: {value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
