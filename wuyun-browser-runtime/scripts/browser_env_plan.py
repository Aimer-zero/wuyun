#!/usr/bin/env python3
"""Generate a modular browser/runtime environment plan for Wuyun.

The script is passive: it checks local capabilities and prints a plan. It does
not install tools, launch browsers, patch fingerprints, or contact targets.
"""
from __future__ import annotations

import argparse
import json
import platform
import shutil
import sys
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass
class Capability:
    name: str
    kind: str
    available: bool
    evidence: str | None
    purpose: str


def which_any(names: list[str]) -> tuple[bool, str | None]:
    for name in names:
        path = shutil.which(name)
        if path:
            return True, path
    return False, None


def app_exists(paths: list[str]) -> tuple[bool, str | None]:
    for item in paths:
        path = Path(item)
        if path.exists():
            return True, str(path)
    return False, None


def detect_capabilities() -> list[Capability]:
    rows: list[Capability] = []
    cli_specs = [
        ("node", ["node"], "JavaScript tooling and Playwright runtime support"),
        ("npm", ["npm", "pnpm", "yarn"], "local JS dependency management"),
        ("python3", ["python3", "python"], "helper scripts and local analyzers"),
        ("curl", ["curl"], "manual scoped HTTP comparison"),
        ("jq", ["jq"], "HAR/JSON inspection"),
        ("mitmproxy", ["mitmproxy", "mitmdump"], "approved HTTP interception workflow"),
        ("burp-suite", ["burpsuite", "BurpSuiteCommunity"], "approved HTTP proxy/replay workflow"),
    ]
    for name, candidates, purpose in cli_specs:
        ok, evidence = which_any(candidates)
        rows.append(Capability(name, "cli", ok, evidence, purpose))

    browser_paths = {
        "Google Chrome": [
            "/Applications/Google Chrome.app",
            str(Path.home() / "Applications/Google Chrome.app"),
        ],
        "Chromium": [
            "/Applications/Chromium.app",
            str(Path.home() / "Applications/Chromium.app"),
        ],
        "Microsoft Edge": [
            "/Applications/Microsoft Edge.app",
            str(Path.home() / "Applications/Microsoft Edge.app"),
        ],
    }
    for name, paths in browser_paths.items():
        ok, evidence = app_exists(paths)
        rows.append(Capability(name, "browser-app", ok, evidence, "interactive browser capture"))
    return rows


PROFILE_STEPS = {
    "browser-runtime": [
        "Create an isolated browser profile for the target and record the profile path.",
        "Capture a baseline HAR/DevTools trace with cache disabled.",
        "Clear Service Workers and cache before reproducing state-sensitive behavior.",
        "Record request IDs, timestamps, redirects, status codes, and decisive headers.",
        "Feed HAR output into `wuyun browser-har <capture.har>`.",
    ],
    "risk-control": [
        "Use an owned browser profile and low-rate requests to reproduce the block/challenge.",
        "Preserve Ray/request/trace IDs and exact timestamps.",
        "Classify challenge, block, rate limit, device binding, origin auth failure, or origin error.",
        "Ask the owner for WAF/CDN logs or temporary test-policy support before further replay.",
        "Do not automate CAPTCHA/Turnstile, rotate proxies, or patch stealth fingerprints.",
    ],
    "proxy": [
        "Use Burp or mitmproxy only with explicit authorization and an isolated profile.",
        "Install interception certificates only in the test profile or lab trust store.",
        "Export HAR or proxy history after redacting unrelated sensitive traffic.",
        "Compare proxied and direct browser behavior one variable at a time.",
    ],
    "js-reverse": [
        "Capture loaded chunks, sourcemap references, request wrappers, and runtime API calls.",
        "Map lazy routes and WebSocket/GraphQL calls from browser network evidence.",
        "Send local bundles to `wuyun js-reverse` and obfuscated files to `wuyun deobfuscate`.",
    ],
    "mobile-hybrid": [
        "Use an emulator or lab device with owned test accounts.",
        "Capture WebView/H5 traffic only inside written scope.",
        "Correlate native bridge calls, H5 routes, and backend API requests.",
        "Avoid SSL-pinning bypass or dynamic hooks unless explicitly authorized for the app/lab.",
    ],
}


def build_payload(profile_name: str) -> dict:
    capabilities = detect_capabilities()
    return {
        "host": {
            "platform": platform.platform(),
            "python": sys.version.split()[0],
        },
        "profile": profile_name,
        "capabilities": [asdict(row) for row in capabilities],
        "plan": PROFILE_STEPS[profile_name],
        "safety": [
            "observation and owner-assisted validation only",
            "no CAPTCHA automation, stealth fingerprint patching, proxy rotation, or high-rate replay",
            "do not retain unrelated cookies, tokens, private bodies, or user data",
        ],
    }


def print_markdown(payload: dict) -> None:
    print("# Wuyun Browser Environment Plan")
    print()
    print(f"- Profile: `{payload['profile']}`")
    print(f"- Platform: `{payload['host']['platform']}`")
    print(f"- Python: `{payload['host']['python']}`")
    print()
    print("## Capabilities")
    for row in payload["capabilities"]:
        status = "yes" if row["available"] else "no"
        evidence = row["evidence"] or "not found"
        print(f"- `{row['name']}` ({row['kind']}): {status}; {evidence}; {row['purpose']}")
    print()
    print("## Plan")
    for step in payload["plan"]:
        print(f"- {step}")
    print()
    print("## Safety")
    for item in payload["safety"]:
        print(f"- {item}")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Generate a passive browser/runtime environment plan.")
    parser.add_argument("--profile", choices=sorted(PROFILE_STEPS), default="browser-runtime")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    args = parser.parse_args(argv)

    payload = build_payload(args.profile)
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print_markdown(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
