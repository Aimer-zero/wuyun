#!/usr/bin/env python3
"""Generate scoped reconnaissance plans without executing network scans."""
from __future__ import annotations

import argparse
import json


def build_plan(domain: str | None, org: str | None, out_of_scope: list[str]) -> dict:
    dorks = []
    if org:
        dorks.extend([
            f'org:{org} "api_key"',
            f'org:{org} "internal" "api"',
            f'org:{org} filename:.env',
            f'org:{org} "Authorization: Bearer"',
        ])
    if domain:
        dorks.extend([
            f'"{domain}" "api"',
            f'"{domain}" "client_id"',
            f'"{domain}" "redirect_uri"',
        ])
    commands = []
    if domain:
        commands.extend([
            f"open https://crt.sh/?q=%25.{domain}",
            f"subfinder -d {domain} -silent -all -o subdomains.txt",
            f"amass enum -passive -d {domain} -o amass-passive.txt",
            f"ffuf -w routes.txt -u https://{domain}/FUZZ -rate 20",
        ])
    return {
        "domain": domain,
        "org": org,
        "out_of_scope": out_of_scope,
        "github_gitlab_dorks": dorks,
        "dry_run_commands": commands,
        "notes": [
            "commands are not executed by this script",
            "review scope and rate limits before active recon",
            "do not collect or retain secrets found in public search results",
        ],
    }


def print_markdown(payload: dict) -> None:
    print("# Wuyun Recon Plan")
    print()
    print(f"- Domain: `{payload['domain'] or ''}`")
    print(f"- Org: `{payload['org'] or ''}`")
    print("## Dorks")
    for item in payload["github_gitlab_dorks"]:
        print(f"- `{item}`")
    print("## Dry-Run Commands")
    for item in payload["dry_run_commands"]:
        print(f"- `{item}`")
    print("## Notes")
    for item in payload["notes"]:
        print(f"- {item}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate scoped recon dry-run plan.")
    parser.add_argument("--domain")
    parser.add_argument("--org")
    parser.add_argument("--out-of-scope", action="append", default=[])
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    payload = build_plan(args.domain, args.org, args.out_of_scope)
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print_markdown(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
