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
        ("js-reverse", "Frontend bundle, sourcemap, runtime API, signing logic, and hardcoded secret triage"),
        ("browser-runtime", "Isolated browser runtime capture, HAR analysis, and risk-control attribution"),
        ("js-deobfuscation", "AST deobfuscation, WASM, and client-side signature/protocol logic triage"),
        ("protocol-analysis", "WebSocket, GraphQL, RPC, streaming, gRPC/protobuf, and HAR protocol inventory"),
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

    audit = sub.add_parser("audit", help="run passive local repository audit")
    audit.add_argument("path", nargs="?", default=".", help="repository root")
    audit.add_argument("--json", action="store_true", help="emit JSON")
    audit.add_argument("--complete-evidence", action="store_true", help="do not compact in-scope evidence")
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

    deobfuscate = sub.add_parser("deobfuscate", help="triage obfuscated JS, WASM, and signing logic")
    deobfuscate.add_argument("path", help="JS/WASM file or directory")
    deobfuscate.add_argument("--json", action="store_true", help="emit JSON")
    deobfuscate.add_argument("--complete-evidence", action="store_true", help="show long evidence lines")
    deobfuscate.set_defaults(func=cmd_deobfuscate)

    protocol = sub.add_parser("protocol", help="passively inventory Web protocols from captures/source")
    protocol.add_argument("path", help="HAR, proxy export, source file, or directory")
    protocol.add_argument("--json", action="store_true", help="emit JSON")
    protocol.set_defaults(func=cmd_protocol)

    report = sub.add_parser("report", help="print a finding/triage/lesson report template")
    report.add_argument("--kind", choices=["finding", "triage", "lesson"], default="finding")
    report.set_defaults(func=lambda args: (print_report_template(args.kind) or 0))

    sub.add_parser("playbooks", help="list Wuyun scenario playbooks").set_defaults(
        func=lambda args: (print_playbooks() or 0)
    )

    return parser


def main(argv: list[str]) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
