#!/usr/bin/env python3
"""Generate a non-executing cloud SSRF probe plan.

The script prints a plan only. It does not send HTTP requests, does not start a
listener, and does not contact cloud metadata services.
"""
from __future__ import annotations

import argparse
import sys
from urllib.parse import quote

PROVIDERS = {
    "aliyun": {
        "metadata": "Aliyun ECS metadata service",
        "lab_paths": [
            "http://100.100.100.200/latest/meta-data/",
            "http://100.100.100.200/latest/meta-data/ram/security-credentials/",
        ],
        "cred_fields": "AccessKeyId, AccessKeySecret, SecurityToken, Expiration",
    },
    "aws": {
        "metadata": "AWS EC2 IMDS",
        "lab_paths": [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        ],
        "cred_fields": "AccessKeyId, SecretAccessKey, Token, Expiration",
    },
    "tencent": {
        "metadata": "Tencent Cloud instance metadata",
        "lab_paths": [
            "http://metadata.tencentyun.com/latest/meta-data/",
            "http://metadata.tencentyun.com/latest/meta-data/cam/security-credentials/",
        ],
        "cred_fields": "TmpSecretId, TmpSecretKey, Token, ExpiredTime",
    },
    "gcp": {
        "metadata": "GCP metadata server",
        "lab_paths": [
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        ],
        "cred_fields": "access_token, expires_in, token_type",
    },
    "azure": {
        "metadata": "Azure Instance Metadata Service",
        "lab_paths": [
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=<resource>",
        ],
        "cred_fields": "access_token, expires_on, resource",
    },
    "generic": {
        "metadata": "unknown cloud metadata service",
        "lab_paths": [],
        "cred_fields": "provider-specific temporary credential fields",
    },
}

BYPASS_CLASSES = [
    "plain controlled callback URL",
    "HTTP to HTTPS and HTTPS to HTTP redirects",
    "redirect to private/link-local target after public validation",
    "IPv6 and IPv4-mapped IPv6 host forms",
    "integer/octal/hex IPv4 host forms",
    "userinfo and parser-confusion host forms",
    "trailing dot, mixed-case, punycode, and encoded separator host forms",
]


def callback_examples(callback_url: str, param: str) -> list[str]:
    encoded = quote(callback_url, safe="")
    return [
        f"{param}={callback_url}",
        f"{param}={encoded}",
        f"{param}=https://example.invalid/redirect?to={encoded}",
    ]


def print_plan(provider: str, mode: str, callback_url: str | None, param: str, include_lab_metadata: bool) -> None:
    info = PROVIDERS[provider]
    print("# Cloud SSRF Probe Plan")
    print()
    print(f"- Mode: `{mode}`")
    print(f"- Provider: `{provider}`")
    print(f"- Target parameter placeholder: `{param}`")
    print("- Execution: `plan only; no requests sent`")
    print()
    print("## Safety Gate")
    if mode in {"online-cloud", "production-safe", "bug-bounty"}:
        print("- Default to controlled callback proof and code/runtime trace.")
        print("- Do not probe metadata endpoints or use exposed credentials unless the task explicitly permits that exact action.")
    elif mode == "ctf-lab":
        print("- Keep probes inside the challenge target and stop after intended artifact recovery.")
    else:
        print("- Use source/config review first; create local tests for parser and redirect behavior.")
    print()
    print("## Step 1 — Confirm server-side fetch")
    if callback_url:
        print("Use a controlled callback URL and record only request metadata:")
        for example in callback_examples(callback_url, param):
            print(f"- `{example}`")
    else:
        print("- Provide `--callback-url https://<controlled-host>/<nonce>` to generate concrete callback examples.")
    print()
    print("## Step 2 — Trace validation boundary")
    print("Record whether validation happens before/after redirects, before/after DNS resolution, and whether the final connect address is checked.")
    print()
    print("## Step 3 — Try one bypass class at a time")
    for item in BYPASS_CLASSES:
        print(f"- {item}")
    print()
    print("## Step 4 — Provider-specific evidence")
    print(f"- Metadata family: {info['metadata']}")
    print(f"- Credential indicators to detect offline: {info['cred_fields']}")
    if include_lab_metadata or mode == "ctf-lab":
        print("- Lab-only metadata paths:")
        for path in info["lab_paths"]:
            print(f"  - `{path}`")
    else:
        print("- Metadata paths intentionally omitted in this mode. Use `--include-lab-metadata` only for explicit lab/CTF scope.")
    print()
    print("## Step 5 — Offline triage")
    print("```bash")
    print("python3 wuyun-cloud-vuln/scripts/detect_cloud_tokens.py evidence.txt")
    print("python3 wuyun-cloud-vuln/scripts/analyze_aliyun_sts_policy.py policy.json")
    print("```")
    print()
    print("## Stop Conditions")
    print("Stop if a response includes credential-shaped fields, account IDs, resource names, private metadata, or business data. Redact and report.")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Generate a non-executing cloud SSRF probe plan.")
    parser.add_argument("--provider", choices=sorted(PROVIDERS), default="generic")
    parser.add_argument("--mode", choices=["online-cloud", "production-safe", "bug-bounty", "ctf-lab", "local-code-audit"], default="production-safe")
    parser.add_argument("--callback-url", help="controlled callback URL with nonce, used only in printed examples")
    parser.add_argument("--param", default="url", help="request parameter name placeholder")
    parser.add_argument("--include-lab-metadata", action="store_true", help="include metadata URLs for explicit lab/CTF planning")
    args = parser.parse_args(argv)

    if args.include_lab_metadata and args.mode not in {"ctf-lab", "local-code-audit"}:
        print("warning: metadata paths are intended for explicit lab/CTF or local reproduction scope", file=sys.stderr)
    print_plan(args.provider, args.mode, args.callback_url, args.param, args.include_lab_metadata)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
