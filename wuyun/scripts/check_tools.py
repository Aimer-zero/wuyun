#!/usr/bin/env python3
"""Wuyun passive tool availability preflight.

This script checks local executables and importable Python modules only. It does
not contact targets, start scanners, open browsers, inspect secrets, or verify
MCP server availability.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import platform
import shutil
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class Tool:
    name: str
    group: str
    purpose: str
    aliases: tuple[str, ...] = ()


@dataclass(frozen=True)
class PyModule:
    name: str
    group: str
    purpose: str
    import_name: str | None = None


TOOLS: tuple[Tool, ...] = (
    Tool("python3", "runtime", "run deterministic helper scripts and custom validators", ("python",)),
    Tool("node", "runtime", "JavaScript parsing, frontend analysis, quick web tooling"),
    Tool("npm", "runtime", "JavaScript tooling installation and local frontend utilities", ("pnpm", "yarn")),
    Tool("ruby", "runtime", "Metasploit helpers and Ruby-based tooling"),
    Tool("go", "runtime", "build Go tools or audit Go projects"),
    Tool("rg", "passive", "fast source and config search", ("ripgrep", "grep")),
    Tool("jq", "passive", "inspect JSON responses, configs, and API schemas"),
    Tool("git", "passive", "inspect history, diffs, ignored files, and provenance"),
    Tool("gh", "passive", "inspect GitHub issues, PRs, and CI metadata"),
    Tool("semgrep", "supply-chain", "static analysis and rule-based code security scanning"),
    Tool("gitleaks", "supply-chain", "secret scanning for repositories and CI"),
    Tool("trivy", "supply-chain", "dependency, container, IaC, and filesystem vulnerability scanning"),
    Tool("pip-audit", "supply-chain", "Python dependency vulnerability audit"),
    Tool("npm-audit", "supply-chain", "Node dependency audit and package lifecycle inspection", ("npm",)),
    Tool("subfinder", "recon", "scoped passive subdomain enumeration"),
    Tool("amass", "recon", "scoped passive/active asset discovery"),
    Tool("curl", "http", "manual HTTP requests for scoped targets", ("wget",)),
    Tool("httpx", "http", "HTTP probing for scoped targets"),
    Tool("mitmproxy", "http-proxy", "approved HTTP interception and HAR/proxy evidence capture", ("mitmdump",)),
    Tool("burpsuite", "http-proxy", "approved HTTP proxy/replay workflow", ("BurpSuiteCommunity", "burp")),
    Tool("caido", "http-proxy", "approved HTTP proxy/replay workflow", ("Caido",)),
    Tool("cloudflared", "cloudflare", "Cloudflare tunnel/owner diagnostics for authorized zones"),
    Tool("wrangler", "cloudflare", "Cloudflare Workers/zone tooling for owner-authorized testing"),
    Tool("aws", "cloud", "AWS CLI for cloud inventory or lab validation"),
    Tool("aliyun", "cloud", "Alibaba Cloud CLI for RAM/STS and lab validation"),
    Tool("tccli", "cloud", "Tencent Cloud CLI for CAM/STS and lab validation"),
    Tool("gcloud", "cloud", "Google Cloud CLI for cloud validation"),
    Tool("az", "cloud", "Azure CLI for cloud validation"),
    Tool("ffuf", "web-enum", "content and parameter discovery for scoped targets"),
    Tool("gobuster", "web-enum", "directory and virtual-host discovery for scoped targets"),
    Tool("dirsearch", "web-enum", "directory discovery for scoped targets"),
    Tool("nuclei", "web-scan", "template-based checks for scoped targets; verify manually"),
    Tool("sqlmap", "web-scan", "SQL injection validation for scoped targets"),
    Tool("jwt_tool", "auth-tools", "JWT lab validation and authorized token review", ("jwt-tool",)),
    Tool("nmap", "network", "service discovery for scoped hosts/ranges"),
    Tool("tshark", "network", "packet/pcap analysis"),
    Tool("openssl", "crypto", "TLS/certificate and crypto primitive inspection"),
    Tool("john", "crypto", "hash/password auditing for test data"),
    Tool("hashcat", "crypto", "hash/password auditing for test data"),
    Tool("file", "binary", "identify binary/file type"),
    Tool("strings", "binary", "extract printable strings from binaries"),
    Tool("checksec", "binary", "binary hardening summary"),
    Tool("gdb", "binary", "dynamic binary debugging", ("lldb",)),
    Tool("ROPgadget", "binary", "ROP gadget search", ("ropper",)),
    Tool("radare2", "binary", "reverse engineering fallback", ("r2",)),
    Tool("objdump", "binary", "disassembly and symbol inspection", ("otool",)),
    Tool("xxd", "binary", "hex inspection"),
    Tool("wasm-objdump", "binary", "WASM import/export and section inspection", ("wasm2wat",)),
    Tool("jadx", "mobile", "Android APK Java/Kotlin decompilation"),
    Tool("apktool", "mobile", "Android APK resource and manifest decoding"),
    Tool("binwalk", "forensics", "firmware/file carving"),
    Tool("foremost", "forensics", "file carving"),
    Tool("volatility", "forensics", "memory forensics", ("vol", "volatility3")),
    Tool("frida", "mobile", "runtime mobile instrumentation", ("frida-ps",)),
    Tool("adb", "mobile", "Android device/app interaction"),
    Tool("docker", "lab", "run local labs and reproducible services"),
    Tool("docker-compose", "lab", "run local lab stacks"),
)

PY_MODULES: tuple[PyModule, ...] = (
    PyModule("requests", "python-http", "scripted HTTP validation", "requests"),
    PyModule("httpx", "python-http", "async/sync scripted HTTP validation", "httpx"),
    PyModule("beautifulsoup4", "python-http", "HTML parsing for passive analysis", "bs4"),
    PyModule("lxml", "python-http", "HTML/XML parsing", "lxml"),
    PyModule("pyyaml", "python-passive", "YAML config parsing", "yaml"),
    PyModule("sourcemap", "python-js-reverse", "offline sourcemap parsing", "sourcemap"),
    PyModule("esprima", "python-js-reverse", "JavaScript AST parsing for static triage", "esprima"),
    PyModule("playwright", "python-browser", "browser automation for authorized runtime capture", "playwright"),
    PyModule("haralyzer", "python-browser", "HAR parsing and browser evidence analysis", "haralyzer"),
    PyModule("protobuf", "python-protocol", "protobuf/gRPC schema and message helpers", "google.protobuf"),
    PyModule("websockets", "python-protocol", "authorized WebSocket replay helper", "websockets"),
    PyModule("jwt", "python-auth", "JWT parsing helpers", "jwt"),
    PyModule("boto3", "python-cloud", "AWS SDK for lab validation and offline helpers", "boto3"),
    PyModule("aliyun-python-sdk-core", "python-cloud", "Alibaba Cloud SDK for lab validation", "aliyunsdkcore"),
    PyModule("tencentcloud-sdk-python", "python-cloud", "Tencent Cloud SDK for lab validation", "tencentcloud"),
    PyModule("google-auth", "python-cloud", "Google Cloud authentication library for cloud validation", "google.auth"),
    PyModule("azure-identity", "python-cloud", "Azure identity library for cloud validation", "azure.identity"),
    PyModule("pyjwt", "python-crypto", "JWT inspection and lab validation", "jwt"),
    PyModule("pycryptodome", "python-crypto", "crypto scripts and CTF/lab proofs", "Crypto"),
    PyModule("z3-solver", "python-crypto", "constraint solving", "z3"),
    PyModule("scapy", "python-network", "packet/protocol crafting in labs", "scapy"),
    PyModule("pwntools", "python-binary", "binary exploitation harnesses in labs", "pwn"),
    PyModule("capstone", "python-binary", "disassembly support", "capstone"),
    PyModule("frida", "python-mobile", "mobile/runtime instrumentation bindings", "frida"),
)

ACTIVE_GROUPS = {"http", "web-enum", "web-scan", "network"}
SPECIALIZED_GROUPS = {
    "binary", "mobile", "forensics", "http-proxy",
    "python-binary", "python-mobile", "python-js-reverse", "python-browser", "python-protocol", "python-auth", "recon", "auth-tools", "supply-chain",
}


def resolve_tool(tool: Tool) -> dict:
    candidates = (tool.name,) + tool.aliases
    for candidate in candidates:
        path = shutil.which(candidate)
        if path:
            return {
                "kind": "cli",
                "name": tool.name,
                "available": True,
                "matched": candidate,
                "path": path,
                "group": tool.group,
                "purpose": tool.purpose,
            }
    return {
        "kind": "cli",
        "name": tool.name,
        "available": False,
        "matched": None,
        "path": None,
        "group": tool.group,
        "purpose": tool.purpose,
    }


def resolve_module(module: PyModule) -> dict:
    import_name = module.import_name or module.name
    try:
        spec = importlib.util.find_spec(import_name)
    except ModuleNotFoundError:
        spec = None
    return {
        "kind": "python-module",
        "name": module.name,
        "available": spec is not None,
        "matched": import_name if spec else None,
        "path": getattr(spec, "origin", None) if spec else None,
        "group": module.group,
        "purpose": module.purpose,
    }


def is_writable(path: Path) -> bool:
    try:
        probe = path / ".wuyun_write_probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
        return True
    except OSError:
        return False


def group_rows(rows: Iterable[dict]) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = {}
    for row in rows:
        grouped.setdefault(row["group"], []).append(row)
    return grouped


def print_markdown(payload: dict) -> None:
    env = payload["environment"]
    print("# Wuyun Tool Preflight")
    print()
    print(f"- CWD: `{env['cwd']}`")
    print(f"- Platform: `{env['platform']}`")
    print(f"- Python: `{env['python']}`")
    print(f"- CWD writable: `{env['cwd_writable']}`")
    print()

    for group, rows in group_rows(payload["capabilities"]).items():
        print(f"## {group}")
        for row in rows:
            status = "✅" if row["available"] else "❌"
            label = "module" if row["kind"] == "python-module" else "cli"
            detail = f"`{row['matched']}` at `{row['path']}`" if row["available"] else "not found"
            print(f"- {status} **{row['name']}** ({label}) — {detail}; {row['purpose']}")
        print()

    missing_active = [
        r["name"]
        for r in payload["capabilities"]
        if not r["available"] and r["group"] in ACTIVE_GROUPS
    ]
    missing_specialized = [
        r["name"]
        for r in payload["capabilities"]
        if not r["available"] and r["group"] in SPECIALIZED_GROUPS
    ]
    missing_cloud = [
        r["name"]
        for r in payload["capabilities"]
        if not r["available"] and r["group"] in {"cloud", "python-cloud"}
    ]
    print("## Practical impact")
    if missing_active:
        print("- Missing active-testing capabilities: " + ", ".join(f"`{x}`" for x in missing_active))
    if missing_specialized:
        print("- Missing specialized capabilities: " + ", ".join(f"`{x}`" for x in missing_specialized))
    if missing_cloud:
        print("- Missing optional cloud capabilities: " + ", ".join(f"`{x}`" for x in missing_cloud))
    if not missing_active and not missing_specialized:
        print("- Core active and specialized local capabilities look present; still verify MCP/tool permissions per task.")
    print("- MCP servers/plugins are host-level capabilities and are not proven by this PATH/module check.")
    print("- If a task needs a missing capability, install/enable it or downgrade validation honestly.")
    print("- Never treat missing tooling as proof that a vulnerability is absent.")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Check local security/research tool availability without running scans.")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of Markdown")
    parser.add_argument("--cwd", default=os.getcwd(), help="workspace path to test for write access")
    args = parser.parse_args(argv)

    cwd = Path(args.cwd).resolve()
    rows = [resolve_tool(tool) for tool in TOOLS] + [resolve_module(module) for module in PY_MODULES]
    payload = {
        "environment": {
            "cwd": str(cwd),
            "platform": platform.platform(),
            "python": sys.version.split()[0],
            "cwd_writable": is_writable(cwd) if cwd.exists() else False,
        },
        "capabilities": rows,
        "summary": {
            "available": sum(1 for r in rows if r["available"]),
            "missing": sum(1 for r in rows if not r["available"]),
        },
    }

    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print_markdown(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
