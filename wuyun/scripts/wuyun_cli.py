#!/usr/bin/env python3
"""Unified local entry point for Wuyun helper workflows.

The CLI is intentionally thin: it orchestrates existing passive helpers and
prints deterministic next steps. It does not scan external targets or install
tools by itself.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parents[1]
PASSTHROUGH_COMMANDS = {
    "cloudflare": ("wuyun", "cloudflare_triage.py"),
    "active-http": ("wuyun-web-api-audit", "active_http_validator.py"),
    "idor-cases": ("wuyun-web-api-audit", "idor_case_generator.py"),
    "deser-chain": ("wuyun-exploit-assist", "deser_chain_builder.py"),
    "sqli-payloads": ("wuyun-exploit-assist", "sqli_payload_gen.py"),
    "ssti-probes": ("wuyun-exploit-assist", "ssti_probe.py"),
    "runtime-hook": ("wuyun-js-reverse", "runtime_hook_capture.py"),
    "ast-transform": ("wuyun-js-deobfuscation", "ast_transform.py"),
    "protocol-replay": ("wuyun-protocol-analysis", "protocol_replay_runner.py"),
    "graphql-plan": ("wuyun-protocol-analysis", "graphql_test_plan.py"),
    "jwt": ("wuyun-auth-audit", "jwt_audit.py"),
    "auth-audit": ("wuyun-auth-audit", "auth_surface_audit.py"),
    "ai-audit": ("wuyun-ai-audit", "ai_surface_audit.py"),
    "ai-cases": ("wuyun-ai-audit", "prompt_case_generator.py"),
    "recon-plan": ("wuyun-recon", "recon_plan.py"),
    "route-wordlist": ("wuyun-recon", "route_wordlist.py"),
    "tool-artifact": ("wuyun-recon", "tool_artifact_generator.py"),
    "evasion-lab": ("wuyun-evasion", "canonicalization_lab.py"),
    "origin-plan": ("wuyun-evasion", "origin_exposure_plan.py"),
    "detection-plan": ("wuyun-evasion", "detection_resilience_plan.py"),
    "redteam-plan": ("wuyun-redteam-ops", "redteam_plan.py"),
    "attack-matrix": ("wuyun-redteam-ops", "attack_path_matrix.py"),
}


def run_script(script: str, args: list[str]) -> int:
    cmd = [sys.executable, str(SCRIPT_DIR / script), *args]
    return subprocess.call(cmd)


def print_report_template(kind: str) -> None:
    title = {
        "finding": "Wuyun Finding",
        "triage": "Wuyun Triage Note",
        "lesson": "Wuyun Learning Note",
    }[kind]
    print(f"# {title}")
    print()
    print("## Summary")
    print("- Status: confirmed | likely | speculative | ruled-out")
    print("- Affected component:")
    print("- Vulnerability class:")
    print()
    print("## Technical Analysis")
    print("- Source/input:")
    print("- Boundary/control:")
    print("- Sink/decision/state change:")
    print("- Preconditions:")
    print()
    print("## Supporting Evidence")
    print("- Files/routes/requests:")
    print("- Minimal proof:")
    print("- Contradictory evidence:")
    print()
    print("## Root Cause")
    print()
    print("## Confidence Level")
    print("- Level: high | medium | low")
    print("- Rationale:")
    print()
    print("## Validation Suggestions")
    print("- Safe next check:")
    print("- High-risk actions intentionally not performed:")
    print()
    print("## Remediation Guidance")
    print("- Code/config fix:")
    print("- Regression test:")
    print()
    print("## Lessons Learned")
    print("- Reusable pattern:")
    print("- False-positive reducer:")


def print_playbooks() -> None:
    playbooks = [
        ("code-audit", "Local repository source/config review"),
        ("web-api", "HTTP/API route, authz, request replay, OpenAPI, and business logic review"),
        ("cloudflare-waf", "Passive Cloudflare/CDN/WAF/challenge classification from headers, bodies, or HAR files"),
        ("exploit-assist", "Canary-safe PoC/reproducer planning after a vulnerability is identified"),
        ("js-reverse", "Frontend bundle, sourcemap, runtime API, signing logic, and hardcoded secret triage"),
        ("browser-runtime", "Isolated browser runtime capture, HAR analysis, and risk-control attribution"),
        ("js-deobfuscation", "AST deobfuscation, WASM, and client-side signature/protocol logic triage"),
        ("protocol-analysis", "WebSocket, GraphQL, RPC, streaming, gRPC/protobuf, and HAR protocol inventory"),
        ("active-validation", "Authorized parameter fuzzing, runtime hooks, AST transforms, and protocol replay"),
        ("auth-audit", "JWT, OAuth/OIDC, SAML, session, cookie, and tenant authorization review"),
        ("ai-audit", "LLM/RAG/agent prompt injection, tool abuse, and AI workflow security"),
        ("recon", "Scoped dorks, CT/subdomain plans, route wordlists, and tool integrations"),
        ("evasion-analysis", "Defensive canonicalization, parser mismatch, and origin exposure planning"),
        ("redteam-ops", "Authorized red-team/purple-team engagement planning and attack-path matrixing"),
        ("chain-mode", "Cross-skill artifact synthesis and safe next-skill chain planning"),
        ("regression-eval", "Local-only helper regression checks for packaging, redaction, Cloudflare triage, and routing"),
        ("knowledge-base", "Reusable cross-project patterns without secrets or private data"),
        ("cloud", "Cloud exposure, SSRF, metadata, temporary credential, and storage/IAM triage"),
        ("production-safe", "Low-impact online review for fragile or business-sensitive targets"),
        ("ctf-lab", "Bounded lab/CTF workflow with replayable steps"),
    ]
    print("# Wuyun Playbooks")
    print()
    for name, description in playbooks:
        print(f"- `{name}`: {description}")
    print()
    print("Use these as mode names in prompts, or select the matching companion skill.")


def cmd_audit(args: argparse.Namespace) -> int:
    audit_args = [str(Path(args.path).resolve())]
    if args.json:
        audit_args.append("--json")
    if args.complete_evidence:
        audit_args.append("--complete-evidence")
    if args.code_only:
        audit_args.append("--code-only")
    if args.max_files:
        audit_args.extend(["--max-files", str(args.max_files)])
    if args.max_size:
        audit_args.extend(["--max-size", str(args.max_size)])
    return run_script("passive_repo_audit.py", audit_args)


def cmd_js(args: argparse.Namespace) -> int:
    script = REPO_ROOT / "wuyun-js-reverse" / "scripts" / "extract_js_surface.py"
    if not script.exists():
        print(f"error: missing JS reverse helper: {script}", file=sys.stderr)
        return 2
    cmd = [sys.executable, str(script), str(Path(args.path).resolve())]
    if args.json:
        cmd.append("--json")
    if args.complete_evidence:
        cmd.append("--complete-evidence")
    return subprocess.call(cmd)


def run_companion_script(skill_name: str, script_name: str, args: list[str]) -> int:
    script = REPO_ROOT / skill_name / "scripts" / script_name
    if not script.exists():
        print(f"error: missing helper: {script}", file=sys.stderr)
        return 2
    return subprocess.call([sys.executable, str(script), *args])


def cmd_browser_env(args: argparse.Namespace) -> int:
    cmd_args = ["--profile", args.profile]
    if args.json:
        cmd_args.append("--json")
    return run_companion_script("wuyun-browser-runtime", "browser_env_plan.py", cmd_args)


def cmd_browser_har(args: argparse.Namespace) -> int:
    cmd_args = [str(Path(args.path).resolve())]
    if args.json:
        cmd_args.append("--json")
    if args.complete_evidence:
        cmd_args.append("--complete-evidence")
    return run_companion_script("wuyun-browser-runtime", "analyze_har.py", cmd_args)


def cmd_deobfuscate(args: argparse.Namespace) -> int:
    cmd_args = [str(Path(args.path).resolve())]
    if args.json:
        cmd_args.append("--json")
    if args.complete_evidence:
        cmd_args.append("--complete-evidence")
    return run_companion_script("wuyun-js-deobfuscation", "deobfuscation_triage.py", cmd_args)


def cmd_protocol(args: argparse.Namespace) -> int:
    cmd_args = [str(Path(args.path).resolve())]
    if args.json:
        cmd_args.append("--json")
    return run_companion_script("wuyun-protocol-analysis", "protocol_inventory.py", cmd_args)


def cmd_passthrough(skill_name: str, script_name: str, args: argparse.Namespace) -> int:
    return run_companion_script(skill_name, script_name, list(args.args))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wuyun",
        description="Local passive entry point for Wuyun research helpers.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    doctor = sub.add_parser("doctor", help="check local tool availability")
    doctor.add_argument("path", nargs="?", default=".", help="workspace path")
    doctor.set_defaults(
        func=lambda args: run_script("check_tools.py", ["--cwd", str(Path(args.path).resolve())])
    )

    init = sub.add_parser("init", help="create project-local .wuyun research memory")
    init.add_argument("path", nargs="?", default=".", help="project root")
    init.add_argument("--force", action="store_true", help="overwrite existing skeleton files")
    init.set_defaults(func=lambda args: run_script("init_memory.py", [str(Path(args.path).resolve())] + (["--force"] if args.force else [])))

    regression = sub.add_parser("eval", help="run local-only Wuyun regression evals")
    regression.add_argument("path", nargs="?", default=str(REPO_ROOT), help="repository root or installed wuyun skill directory")
    regression.set_defaults(func=lambda args: run_script("run_eval.py", [str(Path(args.path).resolve())]))

    audit = sub.add_parser("audit", help="run passive local repository audit")
    audit.add_argument("path", nargs="?", default=".", help="repository root")
    audit.add_argument("--json", action="store_true", help="emit JSON")
    audit.add_argument("--complete-evidence", action="store_true", help="preserve full non-secret context; secrets remain redacted")
    audit.add_argument("--code-only", action="store_true", help="skip docs/examples")
    audit.add_argument("--max-files", type=int, default=0, help="maximum files to inspect")
    audit.add_argument("--max-size", type=int, default=0, help="maximum file size in bytes")
    audit.set_defaults(func=cmd_audit)

    js = sub.add_parser("js-reverse", help="passively extract frontend JS/API surface")
    js.add_argument("path", help="JS file, bundle, sourcemap, or directory")
    js.add_argument("--json", action="store_true", help="emit JSON")
    js.add_argument("--complete-evidence", action="store_true", help="show full matched strings")
    js.set_defaults(func=cmd_js)

    browser_env = sub.add_parser("browser-env", help="plan isolated browser/runtime evidence environment")
    browser_env.add_argument(
        "--profile",
        choices=["browser-runtime", "risk-control", "proxy", "js-reverse", "mobile-hybrid"],
        default="browser-runtime",
    )
    browser_env.add_argument("--json", action="store_true", help="emit JSON")
    browser_env.set_defaults(func=cmd_browser_env)

    har = sub.add_parser("browser-har", help="passively analyze a local HAR capture")
    har.add_argument("path", help="HAR JSON file")
    har.add_argument("--json", action="store_true", help="emit JSON")
    har.add_argument("--complete-evidence", action="store_true", help="show full in-scope headers")
    har.set_defaults(func=cmd_browser_har)

    cloudflare = sub.add_parser("cloudflare", help="passively classify Cloudflare/CDN/WAF/challenge artifacts")
    cloudflare.add_argument("args", nargs=argparse.REMAINDER, help="arguments for cloudflare_triage.py")
    cloudflare.set_defaults(func=lambda args: run_script("cloudflare_triage.py", list(args.args)))

    deobfuscate = sub.add_parser("deobfuscate", help="triage obfuscated JS, WASM, and signing logic")
    deobfuscate.add_argument("path", help="JS/WASM file or directory")
    deobfuscate.add_argument("--json", action="store_true", help="emit JSON")
    deobfuscate.add_argument("--complete-evidence", action="store_true", help="show long evidence lines")
    deobfuscate.set_defaults(func=cmd_deobfuscate)

    protocol = sub.add_parser("protocol", help="passively inventory Web protocols from captures/source")
    protocol.add_argument("path", help="HAR, proxy export, source file, or directory")
    protocol.add_argument("--json", action="store_true", help="emit JSON")
    protocol.set_defaults(func=cmd_protocol)

    active_http = sub.add_parser("active-http", help="authorized low-impact HTTP parameter validation")
    active_http.add_argument("args", nargs=argparse.REMAINDER, help="arguments for active_http_validator.py")
    active_http.set_defaults(func=lambda args: cmd_passthrough("wuyun-web-api-audit", "active_http_validator.py", args))

    idor_cases = sub.add_parser("idor-cases", help="generate IDOR/BOLA case plans from routes")
    idor_cases.add_argument("args", nargs=argparse.REMAINDER, help="arguments for idor_case_generator.py")
    idor_cases.set_defaults(func=lambda args: cmd_passthrough("wuyun-web-api-audit", "idor_case_generator.py", args))

    deser = sub.add_parser("deser-chain", help="generate canary-safe deserialization PoC plan/payload")
    deser.add_argument("args", nargs=argparse.REMAINDER, help="arguments for deser_chain_builder.py")
    deser.set_defaults(func=lambda args: cmd_passthrough("wuyun-exploit-assist", "deser_chain_builder.py", args))

    sqli = sub.add_parser("sqli-payloads", help="generate reviewed SQLi payload and sqlmap plan")
    sqli.add_argument("args", nargs=argparse.REMAINDER, help="arguments for sqli_payload_gen.py")
    sqli.set_defaults(func=lambda args: cmd_passthrough("wuyun-exploit-assist", "sqli_payload_gen.py", args))

    ssti = sub.add_parser("ssti-probes", help="generate inert SSTI canary/arithmetic probes")
    ssti.add_argument("args", nargs=argparse.REMAINDER, help="arguments for ssti_probe.py")
    ssti.set_defaults(func=lambda args: cmd_passthrough("wuyun-exploit-assist", "ssti_probe.py", args))

    runtime_hook = sub.add_parser("runtime-hook", help="generate or run browser runtime observation hooks")
    runtime_hook.add_argument("args", nargs=argparse.REMAINDER, help="arguments for runtime_hook_capture.py")
    runtime_hook.set_defaults(func=lambda args: cmd_passthrough("wuyun-js-reverse", "runtime_hook_capture.py", args))

    ast_transform = sub.add_parser("ast-transform", help="run conservative local JS deobfuscation transforms")
    ast_transform.add_argument("args", nargs=argparse.REMAINDER, help="arguments for ast_transform.py")
    ast_transform.set_defaults(func=lambda args: cmd_passthrough("wuyun-js-deobfuscation", "ast_transform.py", args))

    protocol_replay = sub.add_parser("protocol-replay", help="authorized protocol replay and permission checks")
    protocol_replay.add_argument("args", nargs=argparse.REMAINDER, help="arguments for protocol_replay_runner.py")
    protocol_replay.set_defaults(func=lambda args: cmd_passthrough("wuyun-protocol-analysis", "protocol_replay_runner.py", args))

    graphql_plan = sub.add_parser("graphql-plan", help="generate GraphQL deep-test and replay plans")
    graphql_plan.add_argument("args", nargs=argparse.REMAINDER, help="arguments for graphql_test_plan.py")
    graphql_plan.set_defaults(func=lambda args: cmd_passthrough("wuyun-protocol-analysis", "graphql_test_plan.py", args))

    jwt = sub.add_parser("jwt", help="offline JWT structure/risk triage")
    jwt.add_argument("args", nargs=argparse.REMAINDER, help="arguments for jwt_audit.py")
    jwt.set_defaults(func=lambda args: cmd_passthrough("wuyun-auth-audit", "jwt_audit.py", args))

    auth = sub.add_parser("auth-audit", help="passively extract auth/session surfaces")
    auth.add_argument("args", nargs=argparse.REMAINDER, help="arguments for auth_surface_audit.py")
    auth.set_defaults(func=lambda args: cmd_passthrough("wuyun-auth-audit", "auth_surface_audit.py", args))

    ai = sub.add_parser("ai-audit", help="passively extract AI/LLM attack surface")
    ai.add_argument("args", nargs=argparse.REMAINDER, help="arguments for ai_surface_audit.py")
    ai.set_defaults(func=lambda args: cmd_passthrough("wuyun-ai-audit", "ai_surface_audit.py", args))

    ai_cases = sub.add_parser("ai-cases", help="generate benign AI/LLM security test cases")
    ai_cases.add_argument("args", nargs=argparse.REMAINDER, help="arguments for prompt_case_generator.py")
    ai_cases.set_defaults(func=lambda args: cmd_passthrough("wuyun-ai-audit", "prompt_case_generator.py", args))

    recon = sub.add_parser("recon-plan", help="generate scoped recon dry-run plan")
    recon.add_argument("args", nargs=argparse.REMAINDER, help="arguments for recon_plan.py")
    recon.set_defaults(func=lambda args: cmd_passthrough("wuyun-recon", "recon_plan.py", args))

    wordlist = sub.add_parser("route-wordlist", help="generate route/API wordlist from local artifacts")
    wordlist.add_argument("args", nargs=argparse.REMAINDER, help="arguments for route_wordlist.py")
    wordlist.set_defaults(func=lambda args: cmd_passthrough("wuyun-recon", "route_wordlist.py", args))

    artifact = sub.add_parser("tool-artifact", help="generate Burp/Caido/http, nuclei, sqlmap, or ffuf artifacts")
    artifact.add_argument("args", nargs=argparse.REMAINDER, help="arguments for tool_artifact_generator.py")
    artifact.set_defaults(func=lambda args: cmd_passthrough("wuyun-recon", "tool_artifact_generator.py", args))

    evasion = sub.add_parser("evasion-lab", help="generate benign canonicalization variants for local lab review")
    evasion.add_argument("args", nargs=argparse.REMAINDER, help="arguments for canonicalization_lab.py")
    evasion.set_defaults(func=lambda args: cmd_passthrough("wuyun-evasion", "canonicalization_lab.py", args))

    origin = sub.add_parser("origin-plan", help="generate passive origin exposure review plan")
    origin.add_argument("args", nargs=argparse.REMAINDER, help="arguments for origin_exposure_plan.py")
    origin.set_defaults(func=lambda args: cmd_passthrough("wuyun-evasion", "origin_exposure_plan.py", args))

    detection = sub.add_parser("detection-plan", help="generate safe detection-resilience test matrix")
    detection.add_argument("args", nargs=argparse.REMAINDER, help="arguments for detection_resilience_plan.py")
    detection.set_defaults(func=lambda args: cmd_passthrough("wuyun-evasion", "detection_resilience_plan.py", args))

    redteam = sub.add_parser("redteam-plan", help="generate authorized red-team/purple-team operation plan")
    redteam.add_argument("args", nargs=argparse.REMAINDER, help="arguments for redteam_plan.py")
    redteam.set_defaults(func=lambda args: cmd_passthrough("wuyun-redteam-ops", "redteam_plan.py", args))

    attack_matrix = sub.add_parser("attack-matrix", help="build attack-path matrix from local artifacts")
    attack_matrix.add_argument("args", nargs=argparse.REMAINDER, help="arguments for attack_path_matrix.py")
    attack_matrix.set_defaults(func=lambda args: cmd_passthrough("wuyun-redteam-ops", "attack_path_matrix.py", args))

    kb = sub.add_parser("kb", help="manage reusable Wuyun knowledge entries")
    kb.add_argument("args", nargs=argparse.REMAINDER, help="arguments for knowledge_base.py")
    kb.set_defaults(func=lambda args: run_script("knowledge_base.py", list(args.args)))

    risk = sub.add_parser("risk-report", help="generate CVSS/ATT&CK/ATLAS/PoC helper output")
    risk.add_argument("args", nargs=argparse.REMAINDER, help="arguments for risk_report_helper.py")
    risk.set_defaults(func=lambda args: run_script("risk_report_helper.py", list(args.args)))

    chain = sub.add_parser("chain", help="build safe cross-skill chain plan from local artifacts")
    chain.add_argument("args", nargs=argparse.REMAINDER, help="arguments for chain_planner.py")
    chain.set_defaults(func=lambda args: run_script("chain_planner.py", list(args.args)))

    report = sub.add_parser("report", help="print a finding/triage/lesson report template")
    report.add_argument("--kind", choices=["finding", "triage", "lesson"], default="finding")
    report.set_defaults(func=lambda args: (print_report_template(args.kind) or 0))

    sub.add_parser("playbooks", help="list Wuyun scenario playbooks").set_defaults(
        func=lambda args: (print_playbooks() or 0)
    )

    return parser


def main(argv: list[str]) -> int:
    if argv and argv[0] in PASSTHROUGH_COMMANDS:
        skill_name, script_name = PASSTHROUGH_COMMANDS[argv[0]]
        forwarded = argv[1:]
        if forwarded[:1] == ["--"]:
            forwarded = forwarded[1:]
        return run_companion_script(skill_name, script_name, forwarded)
    if argv and argv[0] == "risk-report":
        forwarded = argv[1:]
        if forwarded[:1] == ["--"]:
            forwarded = forwarded[1:]
        return run_script("risk_report_helper.py", forwarded)
    if argv and argv[0] == "chain":
        forwarded = argv[1:]
        if forwarded[:1] == ["--"]:
            forwarded = forwarded[1:]
        return run_script("chain_planner.py", forwarded)
    if argv and argv[0] == "kb":
        forwarded = argv[1:]
        if forwarded[:1] == ["--"]:
            forwarded = forwarded[1:]
        return run_script("knowledge_base.py", forwarded)
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
