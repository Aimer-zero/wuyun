#!/usr/bin/env python3
"""Generate or execute a Wuyun tool bootstrap plan.

Default mode is dry-run. The script detects missing capabilities and prints
installation commands for selected profiles, but it never installs anything
unless the caller explicitly passes both --apply and --yes.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import platform
import re
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from typing import Iterable


@dataclass(frozen=True)
class ToolSpec:
    name: str
    kind: str  # cli | python | manual
    profiles: tuple[str, ...]
    purpose: str
    detect: tuple[str, ...] = ()
    import_name: str | None = None
    brew: str | None = None
    apt: str | None = None
    pip: str | None = None
    pipx: str | None = None
    manual: str | None = None


TOOLS: tuple[ToolSpec, ...] = (
    ToolSpec("ripgrep", "cli", ("minimal", "web", "ctf", "code"), "fast source search", ("rg",), "", "ripgrep", "ripgrep"),
    ToolSpec("jq", "cli", ("minimal", "web", "cloud"), "JSON inspection", ("jq",), "", "jq", "jq"),
    ToolSpec("git", "cli", ("minimal", "code"), "repository inspection", ("git",), "", "git", "git"),
    ToolSpec("github-cli", "cli", ("recon",), "GitHub code/PR/issue inspection for scoped orgs", ("gh",), "", "gh", "gh"),
    ToolSpec("curl", "cli", ("minimal", "web", "cloud", "evasion"), "manual HTTP requests", ("curl",), "", "curl", "curl"),
    ToolSpec("node", "cli", ("js-reverse",), "local JavaScript parsing and bundle utilities", ("node",), "", "node", "nodejs"),
    ToolSpec("npm", "cli", ("js-reverse",), "install local JavaScript reverse-engineering helpers", ("npm",), "", "node", "npm"),
    ToolSpec("httpx-cli", "cli", ("web", "ctf"), "HTTP probing CLI", ("httpx",), "", "httpx", None, pipx="httpx"),
    ToolSpec("cloudflared", "cli", ("web", "cloudflare", "evasion"), "Cloudflare tunnel/owner diagnostics", ("cloudflared",), "", "cloudflared", None, manual="Install cloudflared from Cloudflare official packages when you control or are authorized for the zone."),
    ToolSpec("wrangler", "cli", ("web", "cloudflare", "evasion"), "Cloudflare Workers/zone tooling for owners", ("wrangler",), "", None, None, manual="Install Wrangler with npm in owner-authorized Cloudflare environments."),
    ToolSpec("ffuf", "cli", ("web", "ctf"), "content/parameter discovery", ("ffuf",), "", "ffuf", "ffuf"),
    ToolSpec("subfinder", "cli", ("recon",), "scoped passive subdomain enumeration", ("subfinder",), "", "subfinder", None, manual="Install ProjectDiscovery subfinder for your OS."),
    ToolSpec("amass", "cli", ("recon",), "scoped asset discovery", ("amass",), "", "amass", "amass"),
    ToolSpec("gobuster", "cli", ("web", "ctf"), "directory/vhost discovery", ("gobuster",), "", "gobuster", "gobuster"),
    ToolSpec("dirsearch", "cli", ("web", "ctf"), "directory discovery", ("dirsearch",), "", "dirsearch", None, pipx="dirsearch"),
    ToolSpec("nuclei", "cli", ("web",), "template-based checks; verify manually", ("nuclei",), "", "nuclei", None, manual="Install ProjectDiscovery nuclei for your OS."),
    ToolSpec("sqlmap", "cli", ("web", "ctf"), "SQL injection validation", ("sqlmap",), "", "sqlmap", "sqlmap", pipx="sqlmap"),
    ToolSpec("jwt_tool", "cli", ("auth", "web", "ctf"), "JWT lab validation and authorized token review", ("jwt_tool", "jwt-tool"), "", None, None, pipx="jwt_tool"),
    ToolSpec("nmap", "cli", ("ctf", "network"), "service discovery for scoped targets", ("nmap",), "", "nmap", "nmap"),
    ToolSpec("tshark", "cli", ("forensics", "network"), "pcap analysis", ("tshark",), "", "wireshark", "tshark"),
    ToolSpec("mitmproxy", "cli", ("browser-runtime", "web", "evasion"), "approved HTTP interception and capture", ("mitmproxy", "mitmdump"), "", "mitmproxy", "mitmproxy", pipx="mitmproxy"),
    ToolSpec("awscli", "cli", ("cloud",), "AWS CLI", ("aws",), "", "awscli", "awscli", pipx="awscli"),
    ToolSpec("aliyun-cli", "cli", ("cloud",), "Alibaba Cloud CLI", ("aliyun",), "", "aliyun-cli", None, manual="Install Aliyun CLI from Alibaba Cloud official packages."),
    ToolSpec("tccli", "cli", ("cloud",), "Tencent Cloud CLI", ("tccli",), "", None, None, pip="tccli"),
    ToolSpec("google-cloud-sdk", "cli", ("cloud",), "Google Cloud CLI", ("gcloud",), "", "google-cloud-sdk", None, manual="Install Google Cloud SDK from official packages."),
    ToolSpec("azure-cli", "cli", ("cloud",), "Azure CLI", ("az",), "", "azure-cli", "azure-cli", pipx="azure-cli"),
    ToolSpec("checksec", "cli", ("binary", "ctf"), "binary hardening summary", ("checksec",), "", "checksec", "checksec"),
    ToolSpec("ropgadget", "cli", ("binary", "ctf"), "ROP gadget search", ("ROPgadget", "ropgadget"), "", None, None, pipx="ROPgadget"),
    ToolSpec("radare2", "cli", ("binary",), "reverse engineering fallback", ("radare2", "r2"), "", "radare2", "radare2"),
    ToolSpec("wabt", "cli", ("js-deobfuscation", "binary"), "WASM inspection tools such as wasm-objdump/wasm2wat", ("wasm-objdump", "wasm2wat"), "", "wabt", "wabt"),
    ToolSpec("binwalk", "cli", ("forensics",), "firmware/file carving", ("binwalk",), "", "binwalk", "binwalk"),
    ToolSpec("foremost", "cli", ("forensics",), "file carving", ("foremost",), "", "foremost", "foremost"),
    ToolSpec("volatility3", "cli", ("forensics",), "memory forensics", ("vol", "volatility3"), "", None, None, pipx="volatility3"),
    ToolSpec("android-platform-tools", "cli", ("mobile",), "Android adb tooling", ("adb",), "", "android-platform-tools", "android-tools-adb"),
    ToolSpec("jadx", "cli", ("mobile",), "Android APK Java/Kotlin decompilation", ("jadx",), "", "jadx", "jadx"),
    ToolSpec("apktool", "cli", ("mobile",), "Android APK resource decoding", ("apktool",), "", "apktool", "apktool"),
    ToolSpec("frida-tools", "cli", ("mobile",), "Frida CLI tools", ("frida", "frida-ps"), "", None, None, pipx="frida-tools"),
    ToolSpec("burp-suite", "manual", ("web",), "HTTP proxy/interception/replay", manual="Install Burp Suite or enable Burp MCP; do not assume scanner coverage without it."),
    ToolSpec("caido", "manual", ("web",), "HTTP proxy/interception/replay", manual="Install Caido or enable a Caido-compatible workflow; import generated .http/raw request artifacts manually."),
    ToolSpec("chrome-or-chromium", "manual", ("browser-runtime",), "interactive browser runtime capture", manual="Install Chrome/Chromium/Edge and use an isolated profile for authorized browser evidence capture."),
    ToolSpec("babel-ast-toolchain", "manual", ("js-deobfuscation",), "Babel AST transform backend", manual="Install @babel/parser @babel/traverse @babel/generator @babel/types in a project-local Node environment for the ast_transform.py Babel backend."),
    ToolSpec("ida-or-ghidra-mcp", "manual", ("binary",), "interactive decompilation", manual="Enable ida-pro-mcp or GhidraMCP for binary reverse engineering tasks."),
    ToolSpec("requests", "python", ("minimal", "web"), "scripted HTTP", import_name="requests", pip="requests"),
    ToolSpec("httpx", "python", ("web",), "async/sync HTTP scripting", import_name="httpx", pip="httpx"),
    ToolSpec("beautifulsoup4", "python", ("web",), "HTML parsing", import_name="bs4", pip="beautifulsoup4"),
    ToolSpec("lxml", "python", ("web",), "HTML/XML parsing", import_name="lxml", pip="lxml"),
    ToolSpec("pyyaml", "python", ("minimal", "code"), "YAML parsing", import_name="yaml", pip="pyyaml"),
    ToolSpec("sourcemap", "python", ("js-reverse",), "offline sourcemap parsing", import_name="sourcemap", pip="sourcemap"),
    ToolSpec("esprima", "python", ("js-reverse",), "JavaScript AST parsing", import_name="esprima", pip="esprima"),
    ToolSpec("playwright", "python", ("browser-runtime",), "authorized browser automation/capture", import_name="playwright", pip="playwright"),
    ToolSpec("haralyzer", "python", ("browser-runtime",), "HAR parsing", import_name="haralyzer", pip="haralyzer"),
    ToolSpec("protobuf", "python", ("protocol",), "protobuf/gRPC schema helpers", import_name="google.protobuf", pip="protobuf"),
    ToolSpec("websockets", "python", ("protocol",), "authorized WebSocket replay helper", import_name="websockets", pip="websockets"),
    ToolSpec("boto3", "python", ("cloud",), "AWS SDK for lab/cloud validation", import_name="boto3", pip="boto3"),
    ToolSpec("aliyun-python-sdk-core", "python", ("cloud",), "Alibaba Cloud SDK", import_name="aliyunsdkcore", pip="aliyun-python-sdk-core"),
    ToolSpec("tencentcloud-sdk-python", "python", ("cloud",), "Tencent Cloud SDK", import_name="tencentcloud", pip="tencentcloud-sdk-python"),
    ToolSpec("google-auth", "python", ("cloud",), "Google auth library", import_name="google.auth", pip="google-auth"),
    ToolSpec("azure-identity", "python", ("cloud",), "Azure identity library", import_name="azure.identity", pip="azure-identity"),
    ToolSpec("pyjwt", "python", ("web", "ctf"), "JWT inspection", import_name="jwt", pip="pyjwt"),
    ToolSpec("pycryptodome", "python", ("ctf", "crypto"), "crypto scripting", import_name="Crypto", pip="pycryptodome"),
    ToolSpec("z3-solver", "python", ("ctf", "crypto"), "constraint solving", import_name="z3", pip="z3-solver"),
    ToolSpec("scapy", "python", ("ctf", "network"), "packet crafting in labs", import_name="scapy", pip="scapy"),
    ToolSpec("pwntools", "python", ("binary", "ctf"), "binary exploit harnesses in labs", import_name="pwn", pip="pwntools"),
    ToolSpec("capstone", "python", ("binary",), "disassembly support", import_name="capstone", pip="capstone"),
    ToolSpec("frida", "python", ("mobile",), "Frida Python bindings", import_name="frida", pip="frida"),
)

PROFILE_DESCRIPTIONS = {
    "minimal": "core passive code review and HTTP scripting basics",
    "web": "Web/API testing helpers and HTTP replay support",
    "cloudflare": "Cloudflare owner-authorized diagnostics and WAF-aware workflow helpers",
    "cloud": "cloud CLI/SDK helpers for lab validation and offline triage",
    "js-reverse": "frontend bundle, sourcemap, API extraction, and signing-logic triage helpers",
    "browser-runtime": "isolated browser runtime capture, HAR analysis, and risk-control attribution helpers",
    "js-deobfuscation": "AST deobfuscation, WASM, and signing protocol triage helpers",
    "protocol": "WebSocket, GraphQL, RPC, gRPC/protobuf, and streaming protocol helpers",
    "ctf": "common CTF/lab enumeration and exploit scripting helpers",
    "binary": "binary triage and exploit development helpers",
    "mobile": "Android/mobile dynamic instrumentation helpers",
    "forensics": "pcap, firmware, and memory forensics helpers",
    "network": "network enumeration and packet analysis helpers",
    "crypto": "crypto/constraint-solving helpers",
    "code": "source-review helpers",
    "recon": "scoped recon planning and local artifact wordlist helpers",
    "auth": "JWT/OAuth/OIDC/SAML/session review helpers",
    "evasion": "defensive canonicalization and owner-assisted origin review helpers",
    "redteam": "authorized red-team/purple-team planning baseline across web, cloud, auth, recon, browser, and protocol helpers",
}


def module_available(import_name: str | None) -> bool:
    if not import_name:
        return False
    try:
        return importlib.util.find_spec(import_name) is not None
    except ModuleNotFoundError:
        return False


def spec_available(spec: ToolSpec) -> bool:
    if spec.kind == "cli":
        return any(shutil.which(candidate) for candidate in spec.detect)
    if spec.kind == "python":
        return module_available(spec.import_name)
    return False


def selected_specs(profiles: Iterable[str], tools: Iterable[str]) -> list[ToolSpec]:
    selected_profiles = set(profiles)
    selected_names = set(tools)
    if "all" in selected_profiles:
        selected_profiles = set(PROFILE_DESCRIPTIONS)
    if "redteam" in selected_profiles:
        selected_profiles.update({"minimal", "web", "cloud", "recon", "auth", "browser-runtime", "protocol"})
    out = []
    for spec in TOOLS:
        if selected_names and spec.name in selected_names:
            out.append(spec)
        elif selected_profiles and selected_profiles.intersection(spec.profiles):
            out.append(spec)
    # preserve order, dedupe by name
    dedup: dict[str, ToolSpec] = {}
    for spec in out:
        dedup.setdefault(spec.name, spec)
    return list(dedup.values())


def platform_manager(preferred: str) -> str:
    if preferred != "auto":
        return preferred
    system = platform.system().lower()
    if system == "darwin" and shutil.which("brew"):
        return "brew"
    if system == "linux" and shutil.which("apt-get"):
        return "apt"
    return "pip"


def install_command(spec: ToolSpec, manager: str, python_bin: str) -> list[str] | None:
    if spec.kind == "manual":
        return None
    if spec.kind == "python":
        if not spec.pip:
            return None
        return [python_bin, "-m", "pip", "install", "--user", spec.pip]
    if manager == "brew" and spec.brew:
        return ["brew", "install", spec.brew]
    if manager == "apt" and spec.apt:
        return ["sudo", "apt-get", "install", "-y", spec.apt]
    if manager == "pipx" and spec.pipx:
        return ["pipx", "install", spec.pipx]
    if spec.pipx and shutil.which("pipx"):
        return ["pipx", "install", spec.pipx]
    if spec.pip:
        return [python_bin, "-m", "pip", "install", "--user", spec.pip]
    return None


def build_plan(specs: list[ToolSpec], manager: str, python_bin: str, only_missing: bool) -> list[dict]:
    rows = []
    for spec in specs:
        available = spec_available(spec)
        if only_missing and available:
            continue
        cmd = install_command(spec, manager, python_bin)
        rows.append({
            "name": spec.name,
            "kind": spec.kind,
            "profiles": list(spec.profiles),
            "purpose": spec.purpose,
            "available": available,
            "command": cmd,
            "manual": spec.manual,
        })
    return rows


def shell_quote(parts: list[str]) -> str:
    return " ".join(shlex_quote(part) for part in parts)


def shlex_quote(value: str) -> str:
    if re_safe(value):
        return value
    return "'" + value.replace("'", "'\\''") + "'"


def re_safe(value: str) -> bool:
    return bool(value) and all(ch.isalnum() or ch in "@%_+=:,./-" for ch in value)


def print_markdown(plan: list[dict], profiles: list[str], manager: str) -> None:
    print("# Wuyun Tool Bootstrap Plan")
    print()
    print(f"- Profiles: `{', '.join(profiles)}`")
    print(f"- Preferred installer: `{manager}`")
    print("- Default behavior: `dry-run only; no tools installed`")
    print()
    if not plan:
        print("No missing tools selected for this plan.")
        return
    print("| Tool | Available | Purpose | Install / Action |")
    print("|---|---:|---|---|")
    for row in plan:
        status = "yes" if row["available"] else "no"
        if row["command"]:
            action = f"`{shell_quote(row['command'])}`"
        else:
            action = row["manual"] or "manual install required"
        print(f"| `{row['name']}` | {status} | {row['purpose']} | {action} |")
    print()
    print("## Apply explicitly")
    print("To execute generated commands, rerun with `--apply --yes`. Review commands first; heavy tools may require admin/network access.")


def print_shell(plan: list[dict]) -> None:
    print("#!/usr/bin/env bash")
    print("set -euo pipefail")
    print("# Generated by Wuyun bootstrap_tools.py. Review before running.")
    for row in plan:
        if row["available"]:
            continue
        if row["command"]:
            print(shell_quote(row["command"]))
        elif row["manual"]:
            print(f"# Manual: {row['name']}: {row['manual']}")


def apply_plan(plan: list[dict], yes: bool) -> int:
    if not yes:
        print("Refusing to install: pass --yes together with --apply after reviewing the plan.", file=sys.stderr)
        return 2
    for row in plan:
        if row["available"] or not row["command"]:
            continue
        print("$ " + shell_quote(row["command"]))
        proc = subprocess.run(row["command"])
        if proc.returncode != 0:
            return proc.returncode
    return 0


def parse_csv(values: list[str]) -> list[str]:
    out: list[str] = []
    for value in values:
        out.extend(part.strip() for part in value.split(",") if part.strip())
    return out


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Generate a dry-run installation plan for Wuyun tool profiles.")
    parser.add_argument("--profile", action="append", default=[], help="profile name or comma-list; default is minimal; use all for every profile")
    parser.add_argument("--tool", action="append", default=[], help="specific tool name or comma-list")
    parser.add_argument("--manager", choices=["auto", "brew", "apt", "pip", "pipx"], default="auto")
    parser.add_argument("--python", default=sys.executable, help="Python executable for pip installs")
    parser.add_argument("--include-installed", action="store_true", help="include already installed capabilities in output")
    parser.add_argument("--emit", choices=["markdown", "json", "shell"], default="markdown")
    parser.add_argument("--apply", action="store_true", help="execute install commands; requires --yes")
    parser.add_argument("--yes", action="store_true", help="confirm execution when --apply is used")
    parser.add_argument("--list-profiles", action="store_true", help="list available profiles and exit")
    args = parser.parse_args(argv)

    if args.list_profiles:
        for name, desc in PROFILE_DESCRIPTIONS.items():
            print(f"{name}: {desc}")
        return 0

    profiles = parse_csv(args.profile) or ["minimal"]
    tools = parse_csv(args.tool)
    unknown = sorted(set(profiles) - set(PROFILE_DESCRIPTIONS) - {"all"})
    if unknown:
        print(f"Unknown profile(s): {', '.join(unknown)}", file=sys.stderr)
        return 2
    unknown_tools = sorted(set(tools) - {spec.name for spec in TOOLS})
    if unknown_tools:
        print(f"Unknown tool(s): {', '.join(unknown_tools)}", file=sys.stderr)
        return 2

    manager = platform_manager(args.manager)
    plan = build_plan(selected_specs(profiles, tools), manager, args.python, only_missing=not args.include_installed)

    if args.emit == "json":
        print(json.dumps({"profiles": profiles, "manager": manager, "dry_run_default": True, "plan": plan}, ensure_ascii=False, indent=2))
    elif args.emit == "shell":
        print_shell(plan)
    else:
        print_markdown(plan, profiles, manager)

    if args.apply:
        return apply_plan(plan, args.yes)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
