#!/usr/bin/env python3
"""Validate the Wuyun skill package before publishing.

This script is local-only and passive. It checks packaging, frontmatter, helper
scripts, stale names, and obvious private-content leaks.
"""
from __future__ import annotations

import argparse
import py_compile
import re
import sys
import tempfile
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


@dataclass
class CheckResult:
    level: str  # PASS | WARN | FAIL
    message: str


REQUIRED_ROOT_FILES = [
    "README.md",
    "LICENSE",
    "install.sh",
    "eval/fixtures/passive_repo/sample_app.py",
    "eval/fixtures/cloudflare/headers.txt",
    "eval/fixtures/cloudflare/body.html",
]

REQUIRED_SKILL_FILES = [
    "SKILL.md",
    "agents/openai.yaml",
    "references/research-methodology.md",
    "references/hypothesis-engine.md",
    "references/report-template.md",
    "references/learning-mechanism.md",
    "references/memory-schema.md",
    "references/tool-matrix.md",
    "references/cloudflare-waf.md",
    "references/safe-validation.md",
    "references/code-audit-patterns.md",
    "references/web-vuln-patterns.md",
    "references/ctf-mode.md",
    "references/chain-mode.md",
    "scripts/check_tools.py",
    "scripts/cloudflare_triage.py",
    "scripts/passive_repo_audit.py",
    "scripts/init_memory.py",
    "scripts/wuyun_cli.py",
    "scripts/bootstrap_tools.py",
    "scripts/quality_gate.py",
    "scripts/run_eval.py",
    "scripts/validate_skill.py",
    "scripts/knowledge_base.py",
    "scripts/risk_report_helper.py",
    "scripts/chain_planner.py",
]

COMPANION_SKILLS: dict[str, list[str]] = {
    "wuyun-cloud-vuln": [
        "SKILL.md",
        "agents/openai.yaml",
        "references/cloud-ssrf-workflow.md",
        "references/aliyun-ssrf-sts.md",
        "references/aws-imds-ssrf.md",
        "references/tencent-cloud-cam-sts.md",
        "references/cloud-permission-impact.md",
        "references/safe-cloud-reporting.md",
        "scripts/detect_cloud_tokens.py",
        "scripts/analyze_aliyun_sts_policy.py",
        "scripts/ssrf_probe_plan.py",
    ],
    "wuyun-web-api-audit": [
        "SKILL.md",
        "agents/openai.yaml",
        "references/bola-idor.md",
        "references/authz-bfla.md",
        "references/injection.md",
        "references/ssrf.md",
        "references/file-upload-path.md",
        "references/xss-ssti.md",
        "references/business-logic.md",
        "references/openapi-review.md",
        "references/cloudflare-waf.md",
        "references/reporting.md",
        "scripts/cloudflare_triage.py",
        "scripts/extract_routes.py",
        "scripts/analyze_openapi.py",
        "scripts/request_diff.py",
        "scripts/active_http_validator.py",
        "scripts/idor_case_generator.py",
    ],
    "wuyun-exploit-assist": [
        "SKILL.md",
        "agents/openai.yaml",
        "references/ssti-payloads.md",
        "references/deser-chains.md",
        "references/sqli-tamper.md",
        "references/cmdi-upload.md",
        "references/xxe-ssrf.md",
        "references/reporting.md",
        "scripts/deser_chain_builder.py",
        "scripts/sqli_payload_gen.py",
        "scripts/ssti_probe.py",
    ],
    "wuyun-js-reverse": [
        "SKILL.md",
        "agents/openai.yaml",
        "references/js-reverse-workflow.md",
        "references/runtime-hooking.md",
        "scripts/extract_js_surface.py",
        "scripts/runtime_hook_capture.py",
    ],
    "wuyun-browser-runtime": [
        "SKILL.md",
        "agents/openai.yaml",
        "references/browser-runtime.md",
        "references/risk-control-triage.md",
        "references/environment-patching.md",
        "scripts/browser_env_plan.py",
        "scripts/analyze_har.py",
    ],
    "wuyun-js-deobfuscation": [
        "SKILL.md",
        "agents/openai.yaml",
        "references/ast-deobfuscation.md",
        "references/signature-protocol.md",
        "references/wasm-analysis.md",
        "scripts/deobfuscation_triage.py",
        "scripts/ast_transform.py",
    ],
    "wuyun-protocol-analysis": [
        "SKILL.md",
        "agents/openai.yaml",
        "references/protocol-workflow.md",
        "references/graphql-websocket.md",
        "scripts/protocol_inventory.py",
        "scripts/protocol_replay_runner.py",
        "scripts/graphql_test_plan.py",
    ],
    "wuyun-auth-audit": [
        "SKILL.md",
        "agents/openai.yaml",
        "references/oauth-oidc-saml.md",
        "references/session-tenant-authz.md",
        "scripts/jwt_audit.py",
        "scripts/auth_surface_audit.py",
    ],
    "wuyun-ai-audit": [
        "SKILL.md",
        "agents/openai.yaml",
        "references/prompt-injection.md",
        "references/rag-agent-tools.md",
        "scripts/ai_surface_audit.py",
        "scripts/prompt_case_generator.py",
    ],
    "wuyun-recon": [
        "SKILL.md",
        "agents/openai.yaml",
        "references/recon-workflow.md",
        "references/tool-integrations.md",
        "scripts/recon_plan.py",
        "scripts/route_wordlist.py",
        "scripts/tool_artifact_generator.py",
    ],
    "wuyun-evasion": [
        "SKILL.md",
        "agents/openai.yaml",
        "references/canonicalization.md",
        "references/origin-exposure.md",
        "scripts/canonicalization_lab.py",
        "scripts/origin_exposure_plan.py",
        "scripts/detection_resilience_plan.py",
    ],
}

IGNORE_DIRS = {
    ".git",
    ".idea",
    ".claude",
    ".codex",
    ".wuyun",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "venv",
    ".venv",
    "dist",
    "build",
}

TEXT_SUFFIXES = {".md", ".yaml", ".yml", ".py", ".sh", ".txt", ".json", ".gitignore", ""}

# Split local private paths so the validator does not flag its own patterns.
PRIVATE_MARKERS = [
    "/Users/" + "zero/",
    "/home/" + "zero/",
    "/private/" + "tmp/",
]

STALE_MARKERS = ["wuyun" + "-ng", "Wuyun" + "-NG", "WUYUN" + "-NG"]

SECRET_PATTERNS = [
    re.compile(r"(?i)aws_access_key_id\s*=\s*AKIA[0-9A-Z]{16}"),
    re.compile(r"(?i)aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{32,}"),
    re.compile(r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"]?[A-Za-z0-9_./+=-]{24,}"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PRIVATE )?PRIVATE KEY-----"),
]


def resolve_paths(path: str | None) -> tuple[Path, Path, str]:
    if path:
        candidate = Path(path).resolve()
        if (candidate / "SKILL.md").exists() and candidate.name == "wuyun":
            parent = candidate.parent
            # Local checkout: <repo>/wuyun plus root docs. Installed skill: skill dir only.
            if (parent / "README.md").exists() and (parent / "wuyun").resolve() == candidate:
                return parent, candidate, "repo"
            return candidate, candidate, "skill"
        return candidate, candidate / "wuyun", "repo"
    # validate_skill.py -> scripts -> wuyun -> repo root
    root = Path(__file__).resolve().parents[2]
    return root, root / "wuyun", "repo"


def add(results: list[CheckResult], level: str, message: str) -> None:
    results.append(CheckResult(level, message))


def iter_text_files(root: Path) -> Iterable[Path]:
    for path in root.rglob("*"):
        if path.is_dir():
            continue
        if any(part in IGNORE_DIRS for part in path.relative_to(root).parts):
            continue
        if path.name == "AGENTS.md":
            continue
        if path.suffix in TEXT_SUFFIXES or path.name in {"LICENSE", ".gitignore"}:
            yield path


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def check_required_files(root: Path, skill_dir: Path, mode: str, results: list[CheckResult]) -> None:
    if mode == "repo":
        for rel in REQUIRED_ROOT_FILES:
            path = root / rel
            add(results, "PASS" if path.exists() else "FAIL", f"root file exists: {rel}")
    else:
        add(results, "PASS", "skill-only install mode; root README/install checks skipped")
    for rel in REQUIRED_SKILL_FILES:
        path = skill_dir / rel
        prefix = "wuyun/" if mode == "repo" else ""
        add(results, "PASS" if path.exists() else "FAIL", f"skill file exists: {prefix}{rel}")


def check_frontmatter(
    skill_dir: Path,
    results: list[CheckResult],
    expected_name: str = "wuyun",
    required_body_markers: tuple[str, ...] = (
        "Scope & Responsibility Model",
        "Execution Modes",
        "Tool Preflight",
    ),
) -> None:
    path = skill_dir / "SKILL.md"
    if not path.exists():
        return
    text = read_text(path)
    if not text.startswith("---\n"):
        add(results, "FAIL", "SKILL.md must start with YAML frontmatter")
        return
    parts = text.split("---", 2)
    if len(parts) < 3:
        add(results, "FAIL", "SKILL.md frontmatter closing delimiter missing")
        return
    frontmatter = parts[1]
    body = parts[2]
    label = skill_dir.name
    keys = [
        line.split(":", 1)[0].strip()
        for line in frontmatter.splitlines()
        if line.strip() and not line.startswith((" ", "\t")) and ":" in line
    ]
    unexpected = sorted(set(keys) - {"name", "description"})
    add(results, "PASS" if not unexpected else "FAIL", f"{label} frontmatter uses only name and description")
    name_pattern = rf"^name:\s*{re.escape(expected_name)}\s*$"
    add(results, "PASS" if re.search(name_pattern, frontmatter, re.M) else "FAIL", f"{label} frontmatter name is {expected_name}")
    add(results, "PASS" if re.search(r"^description:\s*.+", frontmatter, re.M | re.S) else "FAIL", f"{label} frontmatter description exists")
    desc_match = re.search(r"^description:\s*(.+)$", frontmatter, re.M)
    if desc_match:
        desc_len = len(desc_match.group(1).strip())
        add(results, "PASS" if desc_len <= 1024 else "FAIL", f"{label} frontmatter description length is acceptable ({desc_len})")
    for marker in required_body_markers:
        add(results, "PASS" if marker in body else "FAIL", f"{label} body includes {marker}")
    if expected_name == "wuyun":
        add(results, "PASS" if "Artifacts are untrusted" in body else "WARN", "untrusted artifact rule is documented")
        add(results, "PASS" if "Quality Gates" in body else "WARN", "quality gates are documented")
        add(results, "PASS" if "Required Finding Format" in body else "WARN", "finding format is documented")
    else:
        add(results, "PASS" if "Safety Boundary" in body else "WARN", f"{label} safety boundary is documented")
        add(results, "PASS" if "References" in body else "WARN", f"{label} references are documented")
    line_count = len(body.splitlines())
    add(results, "PASS" if line_count <= 500 else "WARN", f"{label}/SKILL.md body stays concise ({line_count} lines)")


def check_openai_yaml(skill_dir: Path, results: list[CheckResult], expected_skill_ref: str = "$wuyun") -> None:
    path = skill_dir / "agents/openai.yaml"
    if not path.exists():
        return
    text = read_text(path)
    label = skill_dir.name
    add(results, "PASS" if "display_name:" in text else "WARN", f"{label} OpenAI display name exists")
    add(results, "PASS" if expected_skill_ref in text else "WARN", f"{label} OpenAI default prompt references {expected_skill_ref}")


def check_reference_integrity(skill_dir: Path, results: list[CheckResult]) -> None:
    skill_text = read_text(skill_dir / "SKILL.md") if (skill_dir / "SKILL.md").exists() else ""
    for match in re.findall(r"`(references/[A-Za-z0-9_.-]+\.md)`", skill_text):
        add(results, "PASS" if (skill_dir / match).exists() else "FAIL", f"referenced file exists: {match}")
    for match in re.findall(r"`(scripts/[A-Za-z0-9_.-]+\.py)(?:\s[^`]*)?`", skill_text):
        add(results, "PASS" if (skill_dir / match).exists() else "FAIL", f"referenced file exists: {match}")


def check_gitignore(root: Path, results: list[CheckResult]) -> None:
    path = root / ".gitignore"
    if not path.exists():
        return
    text = read_text(path)
    for marker in ["AGENTS.md", ".claude/", ".idea/", ".wuyun/", "*.pem", "*.key"]:
        add(results, "PASS" if marker in text else "WARN", f".gitignore protects {marker}")
    add(results, "PASS" if "\nexamples/\n" not in f"\n{text}\n" else "WARN", ".gitignore does not hide publishable examples/")


def check_installer(root: Path, results: list[CheckResult]) -> None:
    path = root / "install.sh"
    if not path.exists():
        return
    text = read_text(path)
    expected = ["wuyun", *COMPANION_SKILLS.keys()]
    for skill in expected:
        add(results, "PASS" if f'"{skill}"' in text else "FAIL", f"installer includes skill: {skill}")
    add(results, "PASS" if "--source-dir" in text else "WARN", "installer supports local --source-dir development installs")


def check_scripts(skill_dir: Path, results: list[CheckResult], root: Path | None = None) -> None:
    scripts = sorted((skill_dir / "scripts").glob("*.py")) if (skill_dir / "scripts").exists() else []
    if not scripts:
        add(results, "FAIL", "no Python helper scripts found")
        return
    with tempfile.TemporaryDirectory(prefix="wuyun-compile-") as tmp:
        tmp_path = Path(tmp)
        for script in scripts:
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("error", SyntaxWarning)
                    compile(read_text(script), str(script), "exec")
                cfile = tmp_path / f"{script.name}.pyc"
                py_compile.compile(str(script), cfile=str(cfile), doraise=True)
                rel = script.relative_to(root) if root and script.is_relative_to(root) else script
                add(results, "PASS", f"Python compiles: {rel}")
            except SyntaxWarning as exc:
                add(results, "FAIL", f"Python syntax warning failed: {script.name}: {exc}")
            except py_compile.PyCompileError as exc:
                add(results, "FAIL", f"Python compile failed: {script.name}: {exc.msg}")


def check_companion_skills(root: Path, results: list[CheckResult]) -> None:
    for name, required_files in COMPANION_SKILLS.items():
        companion = root / name
        add(results, "PASS" if companion.exists() else "FAIL", f"companion skill directory exists: {name}")
        if not companion.exists():
            continue
        for rel in required_files:
            path = companion / rel
            add(results, "PASS" if path.exists() else "FAIL", f"companion file exists: {name}/{rel}")
        check_frontmatter(
            companion,
            results,
            expected_name=name,
            required_body_markers=("Safety Boundary", "Workflow", "References"),
        )
        check_openai_yaml(companion, results, expected_skill_ref=f"${name}")
        check_reference_integrity(companion, results)
        check_scripts(companion, results, root)


def check_content(root: Path, results: list[CheckResult]) -> None:
    for path in iter_text_files(root):
        rel = path.relative_to(root)
        text = read_text(path)
        for marker in STALE_MARKERS:
            if marker in text:
                add(results, "FAIL", f"stale old skill name `{marker}` in {rel}")
        for marker in PRIVATE_MARKERS:
            if marker in text:
                add(results, "FAIL", f"private local path marker in {rel}: {marker}")
        for pattern in SECRET_PATTERNS:
            if pattern.search(text):
                add(results, "FAIL", f"secret-like material found in {rel}; remove before publishing")


def print_results(results: list[CheckResult]) -> int:
    counts = {"PASS": 0, "WARN": 0, "FAIL": 0}
    for result in results:
        counts[result.level] += 1
    print("# Wuyun Skill Validation")
    print()
    print(f"- PASS: {counts['PASS']}")
    print(f"- WARN: {counts['WARN']}")
    print(f"- FAIL: {counts['FAIL']}")
    print()
    for result in results:
        icon = {"PASS": "✅", "WARN": "⚠️", "FAIL": "❌"}[result.level]
        print(f"{icon} [{result.level}] {result.message}")
    return 1 if counts["FAIL"] else 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Validate Wuyun skill packaging before release.")
    parser.add_argument("path", nargs="?", help="repository root; defaults to the parent of the wuyun skill directory")
    args = parser.parse_args(argv)

    root, skill_dir, mode = resolve_paths(args.path)
    results: list[CheckResult] = []

    add(results, "PASS" if root.exists() else "FAIL", f"validation root exists: {root}")
    add(results, "PASS" if skill_dir.exists() else "FAIL", f"skill directory exists: {skill_dir}")
    add(results, "PASS", f"validation mode: {mode}")
    if not root.exists() or not skill_dir.exists():
        return print_results(results)

    check_required_files(root, skill_dir, mode, results)
    check_frontmatter(skill_dir, results)
    check_openai_yaml(skill_dir, results)
    check_reference_integrity(skill_dir, results)
    if mode == "repo":
        check_gitignore(root, results)
        check_installer(root, results)
    check_scripts(skill_dir, results, root)
    if mode == "repo":
        check_companion_skills(root, results)
    check_content(root, results)
    return print_results(results)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
