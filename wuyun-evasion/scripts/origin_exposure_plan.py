#!/usr/bin/env python3
"""Generate a passive owner-assisted origin exposure review plan."""
from __future__ import annotations

import argparse
import json


def build(domain: str, zone_owner: str | None) -> dict:
    return {
        "domain": domain,
        "zone_owner": zone_owner,
        "passive_checks": [
            f"Review certificate transparency for *.{domain} and apex SANs.",
            f"Review SPF/MX/DMARC includes for infrastructure domains related to {domain}.",
            f"Review historical DNS and decommissioned records for {domain} with owner-approved sources.",
            "Inspect CDN/WAF headers, Ray/request IDs, cache status, and origin shielding configuration.",
            "Ask the owner for expected ingress IPs/load balancers and compare against findings.",
        ],
        "dry_run_commands": [
            f"open https://crt.sh/?q=%25.{domain}",
            f"dig TXT {domain}",
            f"dig MX {domain}",
        ],
        "validation_boundary": [
            "do not brute force origin IPs",
            "do not bypass CDN/WAF on production without explicit owner-supplied origin and written approval",
            "use a single harmless metadata request if owner-assisted validation is approved",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate origin exposure review plan.")
    parser.add_argument("--domain", required=True)
    parser.add_argument("--zone-owner")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    payload = build(args.domain, args.zone_owner)
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print("# Wuyun Origin Exposure Plan")
        print()
        print(f"- Domain: `{payload['domain']}`")
        print("## Passive Checks")
        for item in payload["passive_checks"]:
            print(f"- {item}")
        print("## Dry-Run Commands")
        for item in payload["dry_run_commands"]:
            print(f"- `{item}`")
        print("## Validation Boundary")
        for item in payload["validation_boundary"]:
            print(f"- {item}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
