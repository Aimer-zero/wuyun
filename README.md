# Wuyun / 乌云

> 中文 | [English](#english)

Wuyun 是一个面向 AI 编码助手的漏洞研究 Skill。它帮助安全研究人员完成代码审计、在线 Web/API 审计、云安全在线分析、CTF/Lab 调研，并输出有证据、有置信度、有修复建议的结果。

Wuyun 不是一键扫描器，也不是攻击工具包；它更像一套研究流程：先理解系统，再梳理攻击面，生成假设，验证证据，最后形成报告。

## 项目内容

```text
wuyun/                    # 主 Skill：通用漏洞研究流程
wuyun-cloud-vuln/         # 云安全/SSRF/临时凭证分析辅助 Skill
wuyun-web-api-audit/      # Web/API 审计辅助 Skill
wuyun-js-reverse/         # 前端 JS 逆向/API 资产提取辅助 Skill
wuyun-browser-runtime/    # 浏览器运行时/HAR/风控行为归因辅助 Skill
wuyun-js-deobfuscation/   # JS AST 反混淆/签名协议/WASM 辅助 Skill
wuyun-protocol-analysis/  # WebSocket/GraphQL/RPC/协议证据分析辅助 Skill
examples/                 # 使用提示词示例
LICENSE                   # MIT License
```

## 安装

### Codex / OpenAI Skill 目录

```bash
git clone <repo-url> wuyun-skill
mkdir -p ~/.codex/skills
cp -R wuyun-skill/wuyun ~/.codex/skills/wuyun
cp -R wuyun-skill/wuyun-cloud-vuln ~/.codex/skills/wuyun-cloud-vuln
cp -R wuyun-skill/wuyun-web-api-audit ~/.codex/skills/wuyun-web-api-audit
cp -R wuyun-skill/wuyun-js-reverse ~/.codex/skills/wuyun-js-reverse
cp -R wuyun-skill/wuyun-browser-runtime ~/.codex/skills/wuyun-browser-runtime
cp -R wuyun-skill/wuyun-js-deobfuscation ~/.codex/skills/wuyun-js-deobfuscation
cp -R wuyun-skill/wuyun-protocol-analysis ~/.codex/skills/wuyun-protocol-analysis
```

### Claude Skill 目录

```bash
git clone <repo-url> wuyun-skill
mkdir -p ~/.claude/skills
cp -R wuyun-skill/wuyun ~/.claude/skills/wuyun
cp -R wuyun-skill/wuyun-cloud-vuln ~/.claude/skills/wuyun-cloud-vuln
cp -R wuyun-skill/wuyun-web-api-audit ~/.claude/skills/wuyun-web-api-audit
cp -R wuyun-skill/wuyun-js-reverse ~/.claude/skills/wuyun-js-reverse
cp -R wuyun-skill/wuyun-browser-runtime ~/.claude/skills/wuyun-browser-runtime
cp -R wuyun-skill/wuyun-js-deobfuscation ~/.claude/skills/wuyun-js-deobfuscation
cp -R wuyun-skill/wuyun-protocol-analysis ~/.claude/skills/wuyun-protocol-analysis
```

安装后请重启或刷新你的 AI Agent，让它重新发现 Skill。

## 更新 / 升级

如果你保留了本地 clone，进入仓库后拉取最新代码，再重新同步到 Skill 目录：

```bash
cd wuyun-skill
git pull --ff-only
```

更新 Codex / OpenAI Skills：

```bash
rm -rf ~/.codex/skills/wuyun \
  ~/.codex/skills/wuyun-cloud-vuln \
  ~/.codex/skills/wuyun-web-api-audit \
  ~/.codex/skills/wuyun-js-reverse \
  ~/.codex/skills/wuyun-browser-runtime \
  ~/.codex/skills/wuyun-js-deobfuscation \
  ~/.codex/skills/wuyun-protocol-analysis

cp -R wuyun ~/.codex/skills/wuyun
cp -R wuyun-cloud-vuln ~/.codex/skills/wuyun-cloud-vuln
cp -R wuyun-web-api-audit ~/.codex/skills/wuyun-web-api-audit
cp -R wuyun-js-reverse ~/.codex/skills/wuyun-js-reverse
cp -R wuyun-browser-runtime ~/.codex/skills/wuyun-browser-runtime
cp -R wuyun-js-deobfuscation ~/.codex/skills/wuyun-js-deobfuscation
cp -R wuyun-protocol-analysis ~/.codex/skills/wuyun-protocol-analysis
```

更新 Claude Skills：

```bash
rm -rf ~/.claude/skills/wuyun \
  ~/.claude/skills/wuyun-cloud-vuln \
  ~/.claude/skills/wuyun-web-api-audit \
  ~/.claude/skills/wuyun-js-reverse \
  ~/.claude/skills/wuyun-browser-runtime \
  ~/.claude/skills/wuyun-js-deobfuscation \
  ~/.claude/skills/wuyun-protocol-analysis

cp -R wuyun ~/.claude/skills/wuyun
cp -R wuyun-cloud-vuln ~/.claude/skills/wuyun-cloud-vuln
cp -R wuyun-web-api-audit ~/.claude/skills/wuyun-web-api-audit
cp -R wuyun-js-reverse ~/.claude/skills/wuyun-js-reverse
cp -R wuyun-browser-runtime ~/.claude/skills/wuyun-browser-runtime
cp -R wuyun-js-deobfuscation ~/.claude/skills/wuyun-js-deobfuscation
cp -R wuyun-protocol-analysis ~/.claude/skills/wuyun-protocol-analysis
```

更新后请重启或刷新你的 AI Agent。项目级 `.wuyun/` 研究记忆不会被这些命令更新或删除；它通常位于被审计项目目录内，应按项目单独保留。

## 快速使用

### 统一本地入口

```bash
python3 wuyun/scripts/wuyun_cli.py doctor .
python3 wuyun/scripts/wuyun_cli.py init .
python3 wuyun/scripts/wuyun_cli.py audit /path/to/repo
python3 wuyun/scripts/wuyun_cli.py js-reverse /path/to/dist
python3 wuyun/scripts/wuyun_cli.py browser-env --profile risk-control
python3 wuyun/scripts/wuyun_cli.py browser-har capture.har
python3 wuyun/scripts/wuyun_cli.py deobfuscate /path/to/bundle.js
python3 wuyun/scripts/wuyun_cli.py protocol /path/to/capture.har
python3 wuyun/scripts/wuyun_cli.py report --kind finding
```

### 本地代码审计

```text
使用 $wuyun，模式 code-audit。
范围：只检查当前本地仓库的源码、配置和测试。
不要访问外部目标。请输出攻击面、优先级假设、证据、置信度和修复建议。
```

### Web/API 审计

```text
使用 $wuyun 和 $wuyun-web-api-audit。
模式：online-web-api。
目标：https://example.com 或 https://api.example.com。
请进行低影响在线审计，梳理接口、权限、对象 ID、文件上传、SSRF、注入和业务逻辑风险。
```

### 前端 JS 逆向 / API 资产提取

```text
使用 $wuyun 和 $wuyun-js-reverse。
模式：js-reverse。
目标：本地 dist/、bundle.js、sourcemap、HAR 或前端源码。
请被动提取 API、WebSocket、GraphQL、鉴权、签名逻辑、sourcemap 和敏感配置线索，并生成 Web/API 后续验证假设。
```

### 浏览器运行时 / 风控行为归因

```text
使用 $wuyun 和 $wuyun-browser-runtime。
模式：browser-runtime 或 risk-control-triage。
目标：授权浏览器复现、HAR、DevTools trace 或代理导出。
请构建隔离浏览器环境、分析 HAR、识别 CDN/WAF/Bot Defense 行为，输出 owner-assisted validation 建议；不要自动化 CAPTCHA/Turnstile、代理轮换或 stealth 指纹绕过。
```

### JS AST 反混淆 / 签名协议分析

```text
使用 $wuyun、$wuyun-js-reverse 和 $wuyun-js-deobfuscation。
模式：js-deobfuscation。
目标：本地混淆 JS、chunk、sourcemap 或 WASM glue。
请识别字符串数组、控制流平坦化、eval/Function、WebCrypto/CryptoJS、WASM 和签名参数，并输出 AST transform plan 与安全验证假设。
```

### 协议分析

```text
使用 $wuyun 和 $wuyun-protocol-analysis。
模式：protocol-analysis。
目标：HAR、代理导出、GraphQL/protobuf schema、WebSocket 捕获或前端源码。
请被动梳理 WebSocket、Socket.IO、GraphQL、SSE、JSON-RPC、gRPC/protobuf 和上传/流式协议，不要默认重放流量。
```

### Cloudflare WAF 感知 Web/API 审计

```text
使用 $wuyun 和 $wuyun-web-api-audit。
模式：online-web-api。
目标：https://example.com 或 https://api.example.com。
目标前置 Cloudflare WAF/CDN；请先分析响应头、响应体或 HAR，记录 Ray ID，区分 WAF/CDN 行为和源站应用行为，不要进行 CAPTCHA/Turnstile 自动化或高频绕过。
```

### 云安全在线分析 / SSRF 分析

```text
使用 $wuyun 和 $wuyun-cloud-vuln。
模式：online-cloud。
目标：https://example.com 或 example-bucket.oss-cn-hangzhou.aliyuncs.com。
请进行低影响云安全在线分析，关注云指纹、对象存储暴露、SSRF、metadata、临时凭证和权限影响，授权私有报告中输出完整范围内证据。
```

### CTF / Lab

```text
使用 $wuyun，模式 ctf-lab。
这是 CTF/Lab 环境，范围仅限我提供的目标和题目文件。
请进行有边界的枚举、验证和复现，并输出解题步骤。
```

## 常用辅助脚本

```bash
python3 wuyun/scripts/check_tools.py
python3 wuyun/scripts/wuyun_cli.py playbooks
python3 wuyun/scripts/passive_repo_audit.py /path/to/repo --complete-evidence
python3 wuyun-js-reverse/scripts/extract_js_surface.py /path/to/dist
python3 wuyun-browser-runtime/scripts/analyze_har.py capture.har
python3 wuyun-js-deobfuscation/scripts/deobfuscation_triage.py /path/to/bundle.js
python3 wuyun-protocol-analysis/scripts/protocol_inventory.py capture.har
python3 wuyun/scripts/cloudflare_triage.py --headers response-headers.txt --body response-body.html
python3 wuyun/scripts/validate_skill.py
python3 wuyun/scripts/quality_gate.py
```

这些脚本主要用于本地检查、被动审计和发布前验证。请根据你的实际场景和责任边界谨慎使用。

## 适用场景

- 本地源码/配置安全审计
- 前端 JS bundle、sourcemap、H5/SPA API 资产提取和逆向辅助分析
- 浏览器运行时复现、HAR/DevTools 证据分析、CDN/WAF/Bot Defense 行为归因
- JS AST 反混淆、签名协议分析、WASM glue triage
- WebSocket、GraphQL、RPC、gRPC/protobuf、SSE、流式协议和上传协议分析
- 在线 Web/API 安全测试与审计
- Cloudflare CDN/WAF/Bot Management 干扰识别、Ray ID 证据记录和 owner-assisted validation 工作流
- CTF、靶场、实验环境
- 云安全在线分析、云 SSRF、临时凭证、权限影响分析
- 漏洞报告整理、证据归纳和修复建议输出

## 不适用场景

- 用于违法、违规或超出责任边界的第三方测试
- 扫描公网目标或批量探测
- 自动化 CAPTCHA/Turnstile、代理池、stealth 指纹绕控或风控规避
- 获取、导出或保留真实用户数据、业务数据、密钥、Token
- 编写、上传或部署 WebShell、木马、后门、勒索软件等恶意程序
- 造成拒绝服务、破坏数据、影响业务运行的测试

## 免责声明

本项目面向**合法合规的安全研究、教学、代码审计、CTF/Lab 和防御性安全工作**。

本项目只提供研究流程和辅助能力，不替代法律判断或授权判断。使用者应自行确认目标范围、使用权限和适用规则，并对自己的行为负责。因滥用工具、越界测试、破坏系统、泄露数据或其他违法违规行为造成的任何后果，均由使用者自行承担，项目作者和贡献者不承担责任。

请始终遵循：最小化验证、只收集范围内必要证据、授权私有报告中完整输出范围内证据、避免业务影响、及时删除临时数据。

## License

MIT License. See [LICENSE](LICENSE).

---

# English

> [中文](#wuyun--乌云) | English

Wuyun is a vulnerability research Skill for AI coding agents. It helps security researchers perform code audits, online Web/API reviews, online cloud-security analysis, CTF/Lab investigations, and evidence-based reporting.

Wuyun is not a one-click scanner or an offensive toolkit. It is a research workflow: understand the system, map the attack surface, create hypotheses, validate evidence, and write remediation-focused findings.

## Repository Layout

```text
wuyun/                    # Main Skill: general vulnerability research workflow
wuyun-cloud-vuln/         # Companion Skill for cloud SSRF / temporary credential triage
wuyun-web-api-audit/      # Companion Skill for Web/API audits
wuyun-js-reverse/         # Companion Skill for frontend JS reverse engineering and API extraction
wuyun-browser-runtime/    # Companion Skill for browser runtime, HAR, and risk-control attribution
wuyun-js-deobfuscation/   # Companion Skill for JS AST deobfuscation, signatures, and WASM triage
wuyun-protocol-analysis/  # Companion Skill for WebSocket/GraphQL/RPC/protocol evidence
examples/                 # Prompt examples
LICENSE                   # MIT License
```

## Installation

### Codex / OpenAI Skill Directory

```bash
git clone <repo-url> wuyun-skill
mkdir -p ~/.codex/skills
cp -R wuyun-skill/wuyun ~/.codex/skills/wuyun
cp -R wuyun-skill/wuyun-cloud-vuln ~/.codex/skills/wuyun-cloud-vuln
cp -R wuyun-skill/wuyun-web-api-audit ~/.codex/skills/wuyun-web-api-audit
cp -R wuyun-skill/wuyun-js-reverse ~/.codex/skills/wuyun-js-reverse
cp -R wuyun-skill/wuyun-browser-runtime ~/.codex/skills/wuyun-browser-runtime
cp -R wuyun-skill/wuyun-js-deobfuscation ~/.codex/skills/wuyun-js-deobfuscation
cp -R wuyun-skill/wuyun-protocol-analysis ~/.codex/skills/wuyun-protocol-analysis
```

### Claude Skill Directory

```bash
git clone <repo-url> wuyun-skill
mkdir -p ~/.claude/skills
cp -R wuyun-skill/wuyun ~/.claude/skills/wuyun
cp -R wuyun-skill/wuyun-cloud-vuln ~/.claude/skills/wuyun-cloud-vuln
cp -R wuyun-skill/wuyun-web-api-audit ~/.claude/skills/wuyun-web-api-audit
cp -R wuyun-skill/wuyun-js-reverse ~/.claude/skills/wuyun-js-reverse
cp -R wuyun-skill/wuyun-browser-runtime ~/.claude/skills/wuyun-browser-runtime
cp -R wuyun-skill/wuyun-js-deobfuscation ~/.claude/skills/wuyun-js-deobfuscation
cp -R wuyun-skill/wuyun-protocol-analysis ~/.claude/skills/wuyun-protocol-analysis
```

Restart or reload your agent after installation so it can discover the Skills.

## Update / Upgrade

If you kept a local clone, pull the latest code first, then resync the Skill directories:

```bash
cd wuyun-skill
git pull --ff-only
```

Update Codex / OpenAI Skills:

```bash
rm -rf ~/.codex/skills/wuyun \
  ~/.codex/skills/wuyun-cloud-vuln \
  ~/.codex/skills/wuyun-web-api-audit \
  ~/.codex/skills/wuyun-js-reverse \
  ~/.codex/skills/wuyun-browser-runtime \
  ~/.codex/skills/wuyun-js-deobfuscation \
  ~/.codex/skills/wuyun-protocol-analysis

cp -R wuyun ~/.codex/skills/wuyun
cp -R wuyun-cloud-vuln ~/.codex/skills/wuyun-cloud-vuln
cp -R wuyun-web-api-audit ~/.codex/skills/wuyun-web-api-audit
cp -R wuyun-js-reverse ~/.codex/skills/wuyun-js-reverse
cp -R wuyun-browser-runtime ~/.codex/skills/wuyun-browser-runtime
cp -R wuyun-js-deobfuscation ~/.codex/skills/wuyun-js-deobfuscation
cp -R wuyun-protocol-analysis ~/.codex/skills/wuyun-protocol-analysis
```

Update Claude Skills:

```bash
rm -rf ~/.claude/skills/wuyun \
  ~/.claude/skills/wuyun-cloud-vuln \
  ~/.claude/skills/wuyun-web-api-audit \
  ~/.claude/skills/wuyun-js-reverse \
  ~/.claude/skills/wuyun-browser-runtime \
  ~/.claude/skills/wuyun-js-deobfuscation \
  ~/.claude/skills/wuyun-protocol-analysis

cp -R wuyun ~/.claude/skills/wuyun
cp -R wuyun-cloud-vuln ~/.claude/skills/wuyun-cloud-vuln
cp -R wuyun-web-api-audit ~/.claude/skills/wuyun-web-api-audit
cp -R wuyun-js-reverse ~/.claude/skills/wuyun-js-reverse
cp -R wuyun-browser-runtime ~/.claude/skills/wuyun-browser-runtime
cp -R wuyun-js-deobfuscation ~/.claude/skills/wuyun-js-deobfuscation
cp -R wuyun-protocol-analysis ~/.claude/skills/wuyun-protocol-analysis
```

Restart or reload your AI agent after updating. Project-local `.wuyun/` research memory is not updated or deleted by these commands; it usually lives inside the audited project and should be preserved per project.

## Quick Usage

### Unified Local Entry

```bash
python3 wuyun/scripts/wuyun_cli.py doctor .
python3 wuyun/scripts/wuyun_cli.py init .
python3 wuyun/scripts/wuyun_cli.py audit /path/to/repo
python3 wuyun/scripts/wuyun_cli.py js-reverse /path/to/dist
python3 wuyun/scripts/wuyun_cli.py browser-env --profile risk-control
python3 wuyun/scripts/wuyun_cli.py browser-har capture.har
python3 wuyun/scripts/wuyun_cli.py deobfuscate /path/to/bundle.js
python3 wuyun/scripts/wuyun_cli.py protocol /path/to/capture.har
python3 wuyun/scripts/wuyun_cli.py report --kind finding
```

### Local Code Audit

```text
Use $wuyun, mode code-audit.
Scope: only inspect the current local repository source, configs, and tests.
Do not access external targets. Output attack surface, prioritized hypotheses, evidence, confidence, and remediation.
```

### Web/API Audit

```text
Use $wuyun and $wuyun-web-api-audit.
Mode: online-web-api.
Target: https://example.com or https://api.example.com.
Run a low-impact online audit and map endpoints, authorization, object IDs, uploads, SSRF, injection, and business logic risks.
```

### Frontend JS Reverse / API Surface Extraction

```text
Use $wuyun and $wuyun-js-reverse.
Mode: js-reverse.
Target: local dist/, bundle.js, sourcemap, HAR, or frontend source tree.
Passively extract API, WebSocket, GraphQL, auth, signing logic, sourcemap, and sensitive-config leads, then generate Web/API follow-up hypotheses.
```

### Browser Runtime / Risk-Control Attribution

```text
Use $wuyun and $wuyun-browser-runtime.
Mode: browser-runtime or risk-control-triage.
Target: authorized browser reproduction, HAR, DevTools trace, or proxy export.
Build an isolated browser evidence plan, analyze HAR captures, classify CDN/WAF/Bot Defense behavior, and request owner-assisted validation. Do not automate CAPTCHA/Turnstile, rotate proxies, or patch stealth fingerprints.
```

### JS AST Deobfuscation / Signature Protocols

```text
Use $wuyun, $wuyun-js-reverse, and $wuyun-js-deobfuscation.
Mode: js-deobfuscation.
Target: local obfuscated JS, chunks, sourcemaps, or WASM glue.
Identify string arrays, control-flow flattening, eval/Function, WebCrypto/CryptoJS, WASM, and signature parameters, then output an AST transform plan and safe validation hypotheses.
```

### Protocol Analysis

```text
Use $wuyun and $wuyun-protocol-analysis.
Mode: protocol-analysis.
Target: HAR, proxy export, GraphQL/protobuf schema, WebSocket capture, or frontend source.
Passively inventory WebSocket, Socket.IO, GraphQL, SSE, JSON-RPC, gRPC/protobuf, upload, and streaming protocols. Do not replay traffic by default.
```

### Cloudflare WAF-Aware Web/API Audit

```text
Use $wuyun and $wuyun-web-api-audit.
Mode: online-web-api.
Target: https://example.com or https://api.example.com.
The target is behind Cloudflare WAF/CDN. Analyze captured headers/body/HAR first, preserve Ray IDs, separate WAF/CDN behavior from origin behavior, and avoid CAPTCHA/Turnstile automation or high-volume bypass attempts.
```

### Online Cloud Security / SSRF Triage

```text
Use $wuyun and $wuyun-cloud-vuln.
Mode: online-cloud.
Target: https://example.com or example-bucket.s3.amazonaws.com.
Run low-impact online cloud-security analysis for cloud fingerprinting, object storage exposure, SSRF, metadata, temporary credentials, and permission impact. Redact sensitive values.
```

### CTF / Lab

```text
Use $wuyun, mode ctf-lab.
This is a CTF/Lab target. Scope is limited to the target and challenge files I provide.
Perform bounded enumeration, validation, and replayable solution steps.
```

## Helper Scripts

```bash
python3 wuyun/scripts/check_tools.py
python3 wuyun/scripts/wuyun_cli.py playbooks
python3 wuyun/scripts/passive_repo_audit.py /path/to/repo --complete-evidence
python3 wuyun-js-reverse/scripts/extract_js_surface.py /path/to/dist
python3 wuyun-browser-runtime/scripts/analyze_har.py capture.har
python3 wuyun-js-deobfuscation/scripts/deobfuscation_triage.py /path/to/bundle.js
python3 wuyun-protocol-analysis/scripts/protocol_inventory.py capture.har
python3 wuyun/scripts/cloudflare_triage.py --headers response-headers.txt --body response-body.html
python3 wuyun/scripts/validate_skill.py
python3 wuyun/scripts/quality_gate.py
```

Use these scripts for local preflight checks, passive review, and release validation. Stay within your actual scope and responsibility boundary.

## Intended Use

- Local source/config security review
- Frontend JS bundle, sourcemap, H5/SPA API extraction, and reverse-engineering triage
- Browser runtime reproduction, HAR/DevTools evidence analysis, and CDN/WAF/Bot Defense attribution
- JS AST deobfuscation, signature protocol analysis, and WASM glue triage
- WebSocket, GraphQL, RPC, gRPC/protobuf, SSE, streaming protocol, and upload protocol analysis
- Online Web/API testing and auditing
- Cloudflare CDN/WAF/Bot Management interference classification, Ray ID evidence capture, and owner-assisted validation workflow
- CTF, lab, and sandbox research
- Online cloud-security analysis and cloud SSRF / temporary credential impact analysis
- Vulnerability report drafting and remediation guidance

## Not Intended For

- Illegal, abusive, or out-of-scope third-party testing
- Internet-wide scanning or mass probing
- CAPTCHA/Turnstile automation, proxy pools, stealth fingerprint bypass, or risk-control evasion
- Collecting or retaining real user data, business data, secrets, or tokens
- Creating or deploying webshells, trojans, backdoors, ransomware, or malware
- Causing denial of service, data damage, or business disruption

## Disclaimer

This project is intended for **lawful and compliant security research, education, code auditing, CTF/Lab work, and defensive security activities**.

This project provides research workflow guidance and helper capability; it does not replace legal or permission decisions. You are responsible for determining your target scope, usage rights, and applicable rules. The authors and contributors are not responsible for misuse, out-of-scope testing, data exposure, system damage, business disruption, or legal consequences caused by your actions.

Always minimize validation, collect only necessary in-scope evidence, output complete in-scope evidence in authorized private reports, avoid business impact, and remove temporary artifacts when no longer needed.

## License

MIT License. See [LICENSE](LICENSE).
