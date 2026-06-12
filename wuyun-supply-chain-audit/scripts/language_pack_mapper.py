#!/usr/bin/env python3
"""Map repository signals to focused Wuyun code-audit language packs."""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

IGNORE = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}
PACKS = {
    "node-nextjs": {
        "signals": [".js", ".ts", ".tsx", "package.json", "next.config.js", "next.config.mjs"],
        "checks": ["SSR/CSR trust boundary", "server actions/API routes", "prototype pollution", "package lifecycle scripts", "template/render sinks"],
    },
    "python-web": {
        "signals": [".py", "requirements.txt", "pyproject.toml", "manage.py"],
        "checks": ["ORM/query boundaries", "template rendering", "subprocess/shell", "deserialization", "background jobs"],
    },
    "java-spring": {
        "signals": [".java", "pom.xml", "build.gradle", "application.yml", "application.properties"],
        "checks": ["Spring Security", "Actuator exposure", "SpEL", "deserialization", "SSRF clients"],
    },
    "go-web": {
        "signals": [".go", "go.mod"],
        "checks": ["net/http handlers", "template escaping", "context/goroutine lifecycle", "archive extraction", "command execution"],
    },
    "rust": {
        "signals": [".rs", "Cargo.toml"],
        "checks": ["unsafe blocks", "FFI", "panic boundaries", "serde formats", "crypto/key lifecycle"],
    },
    "c-cpp": {
        "signals": [".c", ".cc", ".cpp", ".h", ".hpp", "CMakeLists.txt", "Makefile"],
        "checks": ["memory safety", "integer overflow", "parser boundaries", "unsafe string APIs", "lifetime/ownership"],
    },
    "mobile": {
        "signals": ["AndroidManifest.xml", ".kt", ".swift", ".plist", "build.gradle"],
        "checks": ["WebView bridges", "storage", "deep links", "certificate pinning", "embedded secrets"],
    },
    "smart-contract": {
        "signals": [".sol", ".move", "foundry.toml", "hardhat.config.js"],
        "checks": ["ownership", "reentrancy", "oracle trust", "upgradeability", "signature replay"],
    },
}


def iter_paths(root: Path):
    for path in root.rglob("*"):
        if path.is_dir():
            continue
        rel = path.relative_to(root)
        if set(rel.parts) & IGNORE:
            continue
        yield path


def map_packs(root: Path) -> dict:
    base = root.resolve()
    suffix_counts = Counter()
    filenames = Counter()
    matched = {name: 0 for name in PACKS}
    evidence = {name: [] for name in PACKS}
    for path in iter_paths(base):
        suffix_counts[path.suffix.lower()] += 1
        filenames[path.name] += 1
        for name, pack in PACKS.items():
            for signal in pack["signals"]:
                if signal.startswith(".") and path.suffix.lower() == signal:
                    matched[name] += 1
                    if len(evidence[name]) < 6:
                        evidence[name].append(str(path.relative_to(base)))
                elif path.name == signal:
                    matched[name] += 2
                    if len(evidence[name]) < 6:
                        evidence[name].append(str(path.relative_to(base)))
    packs = []
    for name, score in sorted(matched.items(), key=lambda item: item[1], reverse=True):
        if score <= 0:
            continue
        confidence = "high" if score >= 5 else "medium" if score >= 2 else "low"
        packs.append({
            "pack": name,
            "confidence": confidence,
            "score": score,
            "evidence": sorted(set(evidence[name])),
            "priority_checks": PACKS[name]["checks"],
        })
    return {
        "tool": "wuyun-language-pack-mapper",
        "target": str(base),
        "summary": {"pack_count": len(packs), "top_pack": packs[0]["pack"] if packs else "none"},
        "packs": packs,
        "suffix_counts": dict(suffix_counts.most_common(20)),
        "next_step": "Use the highest-confidence pack checklist during code-audit, then export findings through Wuyun schema.",
    }


def print_markdown(data: dict) -> None:
    print("# Wuyun Language Pack Map")
    print()
    print(f"- Target: `{data['target']}`")
    print(f"- Packs: `{data['summary']['pack_count']}`")
    print(f"- Top pack: `{data['summary']['top_pack']}`")
    print()
    for pack in data["packs"]:
        print(f"## {pack['pack']} ({pack['confidence']})")
        print("- Evidence: " + (", ".join(f"`{x}`" for x in pack["evidence"]) or "none"))
        print("- Priority checks: " + "; ".join(pack["priority_checks"]))
        print()


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Map repository signals to Wuyun language-specific audit packs.")
    parser.add_argument("path", nargs="?", default=".", help="repository path")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    args = parser.parse_args(argv)
    data = map_packs(Path(args.path))
    if args.json:
        print(json.dumps(data, ensure_ascii=False, indent=2))
    else:
        print_markdown(data)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
