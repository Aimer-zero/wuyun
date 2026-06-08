#!/usr/bin/env python3
"""Create a project-local Wuyun memory skeleton.

This is a fallback for environments without managed agent memory. It creates
evidence-pointer-first files and never overwrites existing notes unless --force is used.
"""
from __future__ import annotations

import argparse
import datetime as dt
import sys
from pathlib import Path

MEMORY_TEMPLATE = """# Wuyun Project Memory

Created: {date}

Purpose: store reusable vulnerability research knowledge for this project.
Do not store secrets, tokens, credentials, customer data, raw exploit artifacts, or unrelated personal data.

## Entries

<!-- Add entries using references/memory-schema.md. Keep evidence pointers non-sensitive. -->
"""

PROJECT_TEMPLATE = """# Wuyun Project Profile

Created: {date}

## Scope
- Authorized target:
- Out-of-scope:
- Environment: local | staging | production | lab

## Architecture Notes
- Components:
- Authn/authz model:
- Sensitive assets:
- External integrations:

## Safety Boundary
- Allowed validation:
- Prohibited actions:
- Stop conditions:
"""

ATTACK_SURFACE_TEMPLATE = """# Wuyun Attack Surface

Created: {date}

| Surface | Component | Input control | Trust boundary | Security control | Likely class | Status |
|---|---|---|---|---|---|---|
|  |  |  |  |  |  | candidate |
"""

HYPOTHESES_TEMPLATE = """# Wuyun Hypotheses

Created: {date}

| ID | Claim | Evidence for | Evidence against | Safe validation | Confidence | Status |
|---|---|---|---|---|---|---|
| H-001 |  |  |  |  | low | candidate |
"""

EVIDENCE_INDEX_TEMPLATE = """# Wuyun Evidence Index

Created: {date}

Use this file for pointers to non-sensitive evidence only: file paths, commit IDs,
request IDs, report sections, screenshots, or reproduction notes.
Do not paste secrets, credentials, database contents, or private data.

| ID | Type | Pointer | What it proves | Sensitivity | Related hypothesis/finding |
|---|---|---|---|---|---|
| E-001 | file |  |  | non-sensitive |  |
"""

LESSONS_TEMPLATE = """# Wuyun Lessons Learned

Created: {date}

Use this for reusable patterns, framework behaviors, false-positive reducers, and validation techniques.

## New Entries

<!-- Use references/memory-schema.md when promoting a lesson into memory.md. -->
"""

FALSE_POSITIVES_TEMPLATE = """# Wuyun False-Positive Reducers

Created: {date}

| Signal | Why it was misleading | What ruled it out | Reuse guidance |
|---|---|---|---|
|  |  |  |  |
"""

FINDING_TEMPLATE = """# Finding Draft

Created: {date}

## Summary
- Status: confirmed | likely | speculative | ruled-out
- Affected component:
- Vulnerability class:

## Technical Analysis
- Source/input:
- Boundary/control:
- Sink/decision/state change:

## Supporting Evidence
- Evidence IDs:
- Minimal proof:
- Contradictions:

## Root Cause

## Confidence Level
- Level:
- Rationale:

## Validation Suggestions

## Remediation Guidance

## Lessons Learned
"""


def write_file(path: Path, content: str, force: bool) -> str:
    if path.exists() and not force:
        return f"kept existing {path}"
    path.write_text(content, encoding="utf-8")
    return f"wrote {path}"


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Initialize project-local Wuyun memory files.")
    parser.add_argument("path", nargs="?", default=".", help="project root")
    parser.add_argument("--force", action="store_true", help="overwrite existing memory.md/evidence-index.md")
    args = parser.parse_args(argv)

    root = Path(args.path).resolve()
    if not root.exists() or not root.is_dir():
        print(f"error: not a directory: {root}", file=sys.stderr)
        return 2

    wuyun = root / ".wuyun"
    evidence = wuyun / "evidence"
    findings = wuyun / "findings"
    wuyun.mkdir(exist_ok=True)
    evidence.mkdir(exist_ok=True)
    findings.mkdir(exist_ok=True)

    today = dt.date.today().isoformat()
    messages = [
        write_file(wuyun / "project.md", PROJECT_TEMPLATE.format(date=today), args.force),
        write_file(wuyun / "attack-surface.md", ATTACK_SURFACE_TEMPLATE.format(date=today), args.force),
        write_file(wuyun / "hypotheses.md", HYPOTHESES_TEMPLATE.format(date=today), args.force),
        write_file(wuyun / "memory.md", MEMORY_TEMPLATE.format(date=today), args.force),
        write_file(wuyun / "evidence-index.md", EVIDENCE_INDEX_TEMPLATE.format(date=today), args.force),
        write_file(wuyun / "lessons.md", LESSONS_TEMPLATE.format(date=today), args.force),
        write_file(wuyun / "false-positives.md", FALSE_POSITIVES_TEMPLATE.format(date=today), args.force),
        write_file(findings / "finding-template.md", FINDING_TEMPLATE.format(date=today), args.force),
        f"ensured {evidence}",
        f"ensured {findings}",
    ]
    print("# Wuyun Memory Initialization")
    for message in messages:
        print(f"- {message}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
