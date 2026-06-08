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
wuyun-auth-audit/         # JWT/OAuth/OIDC/SAML/Session/多租户权限辅助 Skill
wuyun-ai-audit/           # LLM/RAG/Agent/提示注入/工具滥用辅助 Skill
wuyun-recon/              # Scope 侦察计划、路由字典、外部工具导出辅助 Skill
wuyun-evasion/            # 防御性规范化差异/源站暴露排查辅助 Skill
LICENSE                   # MIT License
```

## 安装

默认同时安装到 Codex/OpenAI 和 Claude 的 Skill 目录：

```bash
curl -fsSL https://raw.githubusercontent.com/Aimer-zero/wuyun/main/install.sh | bash
```

只安装到某个平台：

```bash
curl -fsSL https://raw.githubusercontent.com/Aimer-zero/wuyun/main/install.sh | bash -s -- --target codex
curl -fsSL https://raw.githubusercontent.com/Aimer-zero/wuyun/main/install.sh | bash -s -- --target claude
```

固定版本安装，不跟随 `main`：

```bash
curl -fsSL https://raw.githubusercontent.com/Aimer-zero/wuyun/main/install.sh | bash -s -- --version v0.2.0
```

安装 fork 或自定义目录：

```bash
curl -fsSL https://raw.githubusercontent.com/Aimer-zero/wuyun/main/install.sh | bash -s -- --repo your-name/wuyun
curl -fsSL https://raw.githubusercontent.com/Aimer-zero/wuyun/main/install.sh | bash -s -- --install-dir ~/.codex/skills
```

安装后请重启或刷新你的 AI Agent，让它重新发现 Skill。安装器依赖 `bash`、`curl` 和 `tar`，不要求用户本地安装 Git。

## 更新 / 升级

更新到 `main` 最新版，重新运行安装命令即可：

```bash
curl -fsSL https://raw.githubusercontent.com/Aimer-zero/wuyun/main/install.sh | bash
```

继续锁定某个版本：

```bash
curl -fsSL https://raw.githubusercontent.com/Aimer-zero/wuyun/main/install.sh | bash -s -- --version v0.2.0
```

查看安装器参数：

```bash
curl -fsSL https://raw.githubusercontent.com/Aimer-zero/wuyun/main/install.sh | bash -s -- --help
```

更新后请重启或刷新你的 AI Agent。项目级 `.wuyun/` 研究记忆不会被安装器更新或删除；它通常位于被审计项目目录内，应按项目单独保留。

## 发布版本

需要给用户固定版本时，先打 tag 并发布 GitHub Release：

```bash
git tag v0.2.0
git push origin v0.2.0
gh release create v0.2.0 --title "v0.2.0" --notes "Wuyun v0.2.0"
```

用户即可安装固定版本：

```bash
curl -fsSL https://raw.githubusercontent.com/Aimer-zero/wuyun/main/install.sh | bash -s -- --version v0.2.0
```

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
python3 wuyun/scripts/wuyun_cli.py active-http --url https://app.example.com/api/item --param id --profile authz-smoke --scope-host app.example.com
python3 wuyun/scripts/wuyun_cli.py runtime-hook generate --output /tmp/wuyun-hook.js
python3 wuyun/scripts/wuyun_cli.py runtime-hook generate --target puppeteer --output /tmp/wuyun-puppeteer-capture.js
python3 wuyun/scripts/wuyun_cli.py runtime-hook generate --target frida-android-webview --scope-host app.example.com --output /tmp/wuyun-frida-webview.js
python3 wuyun/scripts/wuyun_cli.py ast-transform /path/to/obfuscated.js --diff
python3 wuyun/scripts/wuyun_cli.py protocol-replay graphql-case.json --scope-host app.example.com
python3 wuyun/scripts/wuyun_cli.py idor-cases routes.txt --base-url https://app.example.com
python3 wuyun/scripts/wuyun_cli.py graphql-plan --url https://app.example.com/graphql --output graphql-case.json
python3 wuyun/scripts/wuyun_cli.py jwt eyJ...
python3 wuyun/scripts/wuyun_cli.py auth-audit capture.har
python3 wuyun/scripts/wuyun_cli.py ai-audit /path/to/ai-app
python3 wuyun/scripts/wuyun_cli.py ai-cases --channel document --marker WUYUN_CANARY
python3 wuyun/scripts/wuyun_cli.py recon-plan --domain example.com --org example-org
python3 wuyun/scripts/wuyun_cli.py route-wordlist /path/to/dist --output routes.txt
python3 wuyun/scripts/wuyun_cli.py tool-artifact --mode nuclei-template --url https://app.example.com/api/ping --output wuyun-template.yaml
python3 wuyun/scripts/wuyun_cli.py evasion-lab --literal WUYUN_CANONICALIZATION_TEST
python3 wuyun/scripts/wuyun_cli.py origin-plan --domain example.com
python3 wuyun/scripts/wuyun_cli.py risk-report --type idor
python3 wuyun/scripts/wuyun_cli.py kb seed
python3 wuyun/scripts/wuyun_cli.py report --kind finding
```

执行器默认是 dry-run 或本地离线处理。任何会访问目标的命令都需要显式授权参数，例如 `--authorize-active-testing`、`--authorize-runtime-observation` 或 `--authorize-protocol-replay`，并且必须提供匹配的 `--scope-host`。

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

### 主动验证闭环

```text
使用 $wuyun 和 $wuyun-web-api-audit。
模式：authorized-active-validation。
目标：单个明确授权的 API endpoint。
请先 dry-run 生成参数 fuzz / payload 投递 / 响应差异对比计划；只有在我明确提供授权和 scope-host 后，才执行低速、低请求量、单变量主动验证。
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
如需执行本地 transform，请使用 `ast_transform.py` 输出到新文件，不要覆盖原始样本。
```

### 协议分析

```text
使用 $wuyun 和 $wuyun-protocol-analysis。
模式：protocol-analysis。
目标：HAR、代理导出、GraphQL/protobuf schema、WebSocket 捕获或前端源码。
请被动梳理 WebSocket、Socket.IO、GraphQL、SSE、JSON-RPC、gRPC/protobuf 和上传/流式协议，不要默认重放流量。
如需协议重放，请使用 reviewed JSON case file，并显式提供 `--authorize-protocol-replay` 和 `--scope-host`。
```

### 认证 / 授权专项

```text
使用 $wuyun 和 $wuyun-auth-audit。
模式：auth-audit。
目标：HAR、HTTP 请求集合、源码、配置或用户提供的 JWT。
请被动梳理 JWT、OAuth/OIDC、SAML、Session/Cookie、CSRF 和多租户权限边界；JWT 默认只做离线结构风险分析，不爆破密钥。
```

### AI / LLM 应用安全

```text
使用 $wuyun 和 $wuyun-ai-audit。
模式：ai-audit。
目标：LLM、RAG、Agent、工具调用、文档/图片/URL/代码注释输入。
请用 benign canary 设计提示注入、RAG 投毒、Agent 工具滥用和多模态注入验证，不提取真实系统提示、密钥或用户数据。
```

### Scope 侦察与工具链导出

```text
使用 $wuyun 和 $wuyun-recon。
模式：recon。
目标：明确授权的 domain/org 和本地 JS/HAR/路由证据。
请生成 GitHub/GitLab dork、CT、subfinder/amass dry-run、route wordlist、Burp/Caido/raw HTTP、nuclei、sqlmap 和 ffuf 工件；不要默认执行公网扫描。
```

### 防御性 Evasion / 规范化差异分析

```text
使用 $wuyun、$wuyun-browser-runtime 和 $wuyun-evasion。
模式：evasion-analysis。
目标：自有测试环境或明确授权链路。
请使用 benign marker 分析 CDN/WAF/代理/框架/应用的 canonicalization 差异，并输出 owner-assisted origin exposure 排查计划；不要自动绕 WAF、不要 CAPTCHA/Turnstile 自动化、不要代理轮换或源站暴力探测。
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
python3 wuyun-protocol-analysis/scripts/graphql_test_plan.py --url https://app.example.com/graphql --output graphql-case.json
python3 wuyun-auth-audit/scripts/jwt_audit.py <jwt-or-file>
python3 wuyun-auth-audit/scripts/auth_surface_audit.py capture.har
python3 wuyun-ai-audit/scripts/ai_surface_audit.py /path/to/ai-app
python3 wuyun-ai-audit/scripts/prompt_case_generator.py --channel document
python3 wuyun-recon/scripts/recon_plan.py --domain example.com --org example-org
python3 wuyun-recon/scripts/route_wordlist.py /path/to/dist --output routes.txt
python3 wuyun-recon/scripts/tool_artifact_generator.py --mode ffuf-plan --url https://app.example.com
python3 wuyun-evasion/scripts/canonicalization_lab.py
python3 wuyun-evasion/scripts/origin_exposure_plan.py --domain example.com
python3 wuyun/scripts/knowledge_base.py seed
python3 wuyun/scripts/risk_report_helper.py --type idor
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
- JWT、OAuth/OIDC、SAML、Session/Cookie、多租户权限专项审计
- LLM/RAG/Agent、提示注入、工具滥用、多模态输入安全评估
- 授权范围内的侦察计划、路由字典生成和 Burp/Caido/nuclei/sqlmap/ffuf 工件导出
- 自有环境中的规范化差异、WAF/CDN 行为归因和源站暴露 owner-assisted 排查
- 在线 Web/API 安全测试与审计
- Cloudflare CDN/WAF/Bot Management 干扰识别、Ray ID 证据记录和 owner-assisted validation 工作流
- CTF、靶场、实验环境
- 云安全在线分析、云 SSRF、临时凭证、权限影响分析
- 漏洞报告整理、证据归纳和修复建议输出

## 不适用场景

- 用于违法、违规或超出责任边界的第三方测试
- 扫描公网目标或批量探测
- 自动化 CAPTCHA/Turnstile、代理池、stealth 指纹绕控或风控规避
- 自动化 WAF 绕过、源站暴力探测、隐蔽探测或高频规避测试
- 未经明确授权的主动 fuzz、payload 投递、协议重放或浏览器运行时观测
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
wuyun-auth-audit/         # Companion Skill for JWT/OAuth/OIDC/SAML/session/tenant authorization review
wuyun-ai-audit/           # Companion Skill for LLM/RAG/agent/prompt-injection security review
wuyun-recon/              # Companion Skill for scoped recon plans, route wordlists, and tool artifacts
wuyun-evasion/            # Companion Skill for defensive canonicalization/origin-exposure analysis
LICENSE                   # MIT License
```

## Installation

Install into both Codex/OpenAI and Claude skill directories by default:

```bash
curl -fsSL https://raw.githubusercontent.com/Aimer-zero/wuyun/main/install.sh | bash
```

Install for one target only:

```bash
curl -fsSL https://raw.githubusercontent.com/Aimer-zero/wuyun/main/install.sh | bash -s -- --target codex
curl -fsSL https://raw.githubusercontent.com/Aimer-zero/wuyun/main/install.sh | bash -s -- --target claude
```

Install a fixed version instead of tracking `main`:

```bash
curl -fsSL https://raw.githubusercontent.com/Aimer-zero/wuyun/main/install.sh | bash -s -- --version v0.2.0
```

Install a fork or custom directory:

```bash
curl -fsSL https://raw.githubusercontent.com/Aimer-zero/wuyun/main/install.sh | bash -s -- --repo your-name/wuyun
curl -fsSL https://raw.githubusercontent.com/Aimer-zero/wuyun/main/install.sh | bash -s -- --install-dir ~/.codex/skills
```

Restart or reload your agent after installation so it can discover the Skills. The installer requires `bash`, `curl`, and `tar`; users do not need Git locally.

## Update / Upgrade

To update to the latest `main`, rerun the installer:

```bash
curl -fsSL https://raw.githubusercontent.com/Aimer-zero/wuyun/main/install.sh | bash
```

To keep a fixed version:

```bash
curl -fsSL https://raw.githubusercontent.com/Aimer-zero/wuyun/main/install.sh | bash -s -- --version v0.2.0
```

Show installer options:

```bash
curl -fsSL https://raw.githubusercontent.com/Aimer-zero/wuyun/main/install.sh | bash -s -- --help
```

Restart or reload your AI agent after updating. Project-local `.wuyun/` research memory is not updated or deleted by the installer; it usually lives inside the audited project and should be preserved per project.

## Release Versions

When users need a fixed version, create a tag and GitHub Release:

```bash
git tag v0.2.0
git push origin v0.2.0
gh release create v0.2.0 --title "v0.2.0" --notes "Wuyun v0.2.0"
```

Users can then install that fixed version:

```bash
curl -fsSL https://raw.githubusercontent.com/Aimer-zero/wuyun/main/install.sh | bash -s -- --version v0.2.0
```

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
python3 wuyun/scripts/wuyun_cli.py active-http --url https://app.example.com/api/item --param id --profile authz-smoke --scope-host app.example.com
python3 wuyun/scripts/wuyun_cli.py runtime-hook generate --output /tmp/wuyun-hook.js
python3 wuyun/scripts/wuyun_cli.py runtime-hook generate --target puppeteer --output /tmp/wuyun-puppeteer-capture.js
python3 wuyun/scripts/wuyun_cli.py runtime-hook generate --target frida-android-webview --scope-host app.example.com --output /tmp/wuyun-frida-webview.js
python3 wuyun/scripts/wuyun_cli.py ast-transform /path/to/obfuscated.js --diff
python3 wuyun/scripts/wuyun_cli.py protocol-replay graphql-case.json --scope-host app.example.com
python3 wuyun/scripts/wuyun_cli.py idor-cases routes.txt --base-url https://app.example.com
python3 wuyun/scripts/wuyun_cli.py graphql-plan --url https://app.example.com/graphql --output graphql-case.json
python3 wuyun/scripts/wuyun_cli.py jwt eyJ...
python3 wuyun/scripts/wuyun_cli.py auth-audit capture.har
python3 wuyun/scripts/wuyun_cli.py ai-audit /path/to/ai-app
python3 wuyun/scripts/wuyun_cli.py ai-cases --channel document --marker WUYUN_CANARY
python3 wuyun/scripts/wuyun_cli.py recon-plan --domain example.com --org example-org
python3 wuyun/scripts/wuyun_cli.py route-wordlist /path/to/dist --output routes.txt
python3 wuyun/scripts/wuyun_cli.py tool-artifact --mode nuclei-template --url https://app.example.com/api/ping --output wuyun-template.yaml
python3 wuyun/scripts/wuyun_cli.py evasion-lab --literal WUYUN_CANONICALIZATION_TEST
python3 wuyun/scripts/wuyun_cli.py origin-plan --domain example.com
python3 wuyun/scripts/wuyun_cli.py risk-report --type idor
python3 wuyun/scripts/wuyun_cli.py kb seed
python3 wuyun/scripts/wuyun_cli.py report --kind finding
```

Executors default to dry-run or local offline processing. Any command that contacts a target requires an explicit authorization flag such as `--authorize-active-testing`, `--authorize-runtime-observation`, or `--authorize-protocol-replay`, plus a matching `--scope-host`.

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

### Active Validation Loop

```text
Use $wuyun and $wuyun-web-api-audit.
Mode: authorized-active-validation.
Target: one explicitly authorized API endpoint.
First dry-run a parameter fuzz / payload delivery / response-diff plan. Execute only after I provide explicit authorization and scope-host, using low-rate, low-count, one-variable-at-a-time probes.
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
For local transforms, use `ast_transform.py` and write to a new file; do not overwrite the original sample.
```

### Protocol Analysis

```text
Use $wuyun and $wuyun-protocol-analysis.
Mode: protocol-analysis.
Target: HAR, proxy export, GraphQL/protobuf schema, WebSocket capture, or frontend source.
Passively inventory WebSocket, Socket.IO, GraphQL, SSE, JSON-RPC, gRPC/protobuf, upload, and streaming protocols. Do not replay traffic by default.
For protocol replay, use a reviewed JSON case file and explicitly provide `--authorize-protocol-replay` and `--scope-host`.
```

### Authentication / Authorization Review

```text
Use $wuyun and $wuyun-auth-audit.
Mode: auth-audit.
Target: HAR, HTTP request collection, source/config tree, or user-provided JWT.
Passively inventory JWT, OAuth/OIDC, SAML, session/cookie, CSRF, and tenant boundaries. JWT review is offline structural triage by default; do not brute force secrets.
```

### AI / LLM Application Security

```text
Use $wuyun and $wuyun-ai-audit.
Mode: ai-audit.
Target: LLM, RAG, agent, tool-use, document/image/URL/code-comment input workflows.
Generate benign canary tests for prompt injection, RAG poisoning, agent tool abuse, and multimodal injection without extracting real system prompts, secrets, or user data.
```

### Scoped Recon And Tool Artifacts

```text
Use $wuyun and $wuyun-recon.
Mode: recon.
Target: explicitly authorized domain/org and local JS/HAR/route evidence.
Generate GitHub/GitLab dorks, CT plans, subfinder/amass dry-runs, route wordlists, Burp/Caido/raw HTTP, nuclei, sqlmap, and ffuf artifacts. Do not execute public scanning by default.
```

### Defensive Evasion / Canonicalization Analysis

```text
Use $wuyun, $wuyun-browser-runtime, and $wuyun-evasion.
Mode: evasion-analysis.
Target: owned lab or explicitly authorized CDN/WAF/application path.
Use benign markers to analyze canonicalization differences across CDN/WAF/proxy/framework/application layers, and produce an owner-assisted origin exposure plan. Do not automate WAF bypass, CAPTCHA/Turnstile handling, proxy rotation, or origin brute forcing.
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
python3 wuyun-protocol-analysis/scripts/graphql_test_plan.py --url https://app.example.com/graphql --output graphql-case.json
python3 wuyun-auth-audit/scripts/jwt_audit.py <jwt-or-file>
python3 wuyun-auth-audit/scripts/auth_surface_audit.py capture.har
python3 wuyun-ai-audit/scripts/ai_surface_audit.py /path/to/ai-app
python3 wuyun-ai-audit/scripts/prompt_case_generator.py --channel document
python3 wuyun-recon/scripts/recon_plan.py --domain example.com --org example-org
python3 wuyun-recon/scripts/route_wordlist.py /path/to/dist --output routes.txt
python3 wuyun-recon/scripts/tool_artifact_generator.py --mode ffuf-plan --url https://app.example.com
python3 wuyun-evasion/scripts/canonicalization_lab.py
python3 wuyun-evasion/scripts/origin_exposure_plan.py --domain example.com
python3 wuyun/scripts/knowledge_base.py seed
python3 wuyun/scripts/risk_report_helper.py --type idor
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
- JWT, OAuth/OIDC, SAML, session/cookie, and tenant authorization review
- LLM/RAG/agent prompt injection, tool abuse, and multimodal input security review
- Scoped recon planning, route wordlists, and Burp/Caido/nuclei/sqlmap/ffuf artifact generation
- Owned-lab canonicalization, WAF/CDN behavior attribution, and owner-assisted origin exposure review
- Online Web/API testing and auditing
- Cloudflare CDN/WAF/Bot Management interference classification, Ray ID evidence capture, and owner-assisted validation workflow
- CTF, lab, and sandbox research
- Online cloud-security analysis and cloud SSRF / temporary credential impact analysis
- Vulnerability report drafting and remediation guidance

## Not Intended For

- Illegal, abusive, or out-of-scope third-party testing
- Internet-wide scanning or mass probing
- CAPTCHA/Turnstile automation, proxy pools, stealth fingerprint bypass, or risk-control evasion
- Automated WAF bypass, origin brute forcing, stealth probing, or high-rate evasion testing
- Active fuzzing, payload delivery, protocol replay, or browser runtime observation without explicit authorization
- Collecting or retaining real user data, business data, secrets, or tokens
- Creating or deploying webshells, trojans, backdoors, ransomware, or malware
- Causing denial of service, data damage, or business disruption

## Disclaimer

This project is intended for **lawful and compliant security research, education, code auditing, CTF/Lab work, and defensive security activities**.

This project provides research workflow guidance and helper capability; it does not replace legal or permission decisions. You are responsible for determining your target scope, usage rights, and applicable rules. The authors and contributors are not responsible for misuse, out-of-scope testing, data exposure, system damage, business disruption, or legal consequences caused by your actions.

Always minimize validation, collect only necessary in-scope evidence, output complete in-scope evidence in authorized private reports, avoid business impact, and remove temporary artifacts when no longer needed.

## License

MIT License. See [LICENSE](LICENSE).
