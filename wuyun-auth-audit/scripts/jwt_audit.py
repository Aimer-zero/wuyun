#!/usr/bin/env python3
"""Offline JWT structure and risk triage for Wuyun Auth Audit."""
from __future__ import annotations

import argparse
import base64
import json
import re
import sys
import time
from pathlib import Path
from typing import Any


JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")


def b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def decode_part(value: str) -> Any:
    return json.loads(b64url_decode(value).decode("utf-8", errors="replace"))


def compact(value: Any) -> Any:
    if isinstance(value, dict):
        out = {}
        for key, child in value.items():
            if re.search(r"(?i)token|secret|password|credential|session|cookie", str(key)):
                out[key] = "<compact-sensitive-value>"
            else:
                out[key] = compact(child)
        return out
    if isinstance(value, list):
        return [compact(item) for item in value[:20]]
    return value


def find_token(input_value: str) -> str:
    path = Path(input_value)
    try:
        is_file = path.exists()
    except (OSError, ValueError):
        is_file = False
    text = path.read_text(encoding="utf-8", errors="replace") if is_file else input_value
    match = JWT_RE.search(text.strip())
    if not match:
        raise ValueError("no JWT-looking token found")
    return match.group(0)


def analyze(token: str, complete: bool) -> dict:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("JWT must have three segments")
    header = decode_part(parts[0])
    payload = decode_part(parts[1])
    now = int(time.time())
    risks = []
    alg = str(header.get("alg", "")).lower()
    if alg in {"none", ""}:
        risks.append("alg-none-or-missing")
    if "kid" in header:
        kid = str(header["kid"])
        if any(item in kid for item in ["../", "..\\", "/", "\\", "\x00"]):
            risks.append("kid-path-or-injection-shape")
    for key in ["jku", "x5u", "jwks_uri"]:
        if key in header:
            risks.append(f"remote-key-reference-{key}")
    if "exp" not in payload:
        risks.append("missing-exp")
    elif isinstance(payload.get("exp"), int) and payload["exp"] < now:
        risks.append("expired-token")
    if "aud" not in payload:
        risks.append("missing-aud")
    if "iss" not in payload:
        risks.append("missing-iss")
    if "sub" not in payload:
        risks.append("missing-sub")
    if alg.startswith("hs"):
        risks.append("hmac-token-review-key-management")
    authorized_test_plan = [
        "Verify signature with trusted application keys or JWKS in a lab harness.",
        "Attempt alg/kid/jku/x5u/jwks_uri negative tests only against owned lab tokens or explicitly authorized test tenants.",
        "If weak-key assessment is approved for a lab token, run it out-of-band with strict rate and data-retention limits.",
    ]
    return {
        "header": header if complete else compact(header),
        "payload": payload if complete else compact(payload),
        "signature_length": len(parts[2]),
        "risks": sorted(set(risks)),
        "authorized_test_plan": authorized_test_plan,
        "limits": [
            "offline structural analysis only",
            "does not verify signature without trusted keys",
            "does not brute force secrets",
        ],
    }


def print_markdown(payload: dict) -> None:
    print("# Wuyun JWT Audit")
    print()
    print("## Header")
    print("```json")
    print(json.dumps(payload["header"], ensure_ascii=False, indent=2))
    print("```")
    print("## Payload")
    print("```json")
    print(json.dumps(payload["payload"], ensure_ascii=False, indent=2))
    print("```")
    print("## Risks")
    if payload["risks"]:
        for risk in payload["risks"]:
            print(f"- `{risk}`")
    else:
        print("- No configured structural risks found.")
    print("## Limits")
    for item in payload["limits"]:
        print(f"- {item}")
    print("## Authorized Test Plan")
    for item in payload["authorized_test_plan"]:
        print(f"- {item}")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Offline JWT structure/risk triage.")
    parser.add_argument("token_or_file")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--complete", action="store_true", help="show complete in-scope values")
    args = parser.parse_args(argv)
    try:
        payload = analyze(find_token(args.token_or_file), complete=args.complete)
    except (OSError, ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print_markdown(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
