# Wuyun / 乌云

> 中文 | [English](#english)

Wuyun 是一个面向 AI 编码助手的漏洞研究 Skill 套件。它把“安全审计”拆成可复用的研究流程：先理解系统，再发现攻击面、生成假设、低影响验证、输出可修复报告。

核心目标：让 Codex/Claude 这类 Agent 在**合法授权、CTF/Lab、本地代码审计、防御性评估**中更像研究员，而不是只跑扫描器。

## 60 秒上手

```bash
curl -fsSL https://raw.githubusercontent.com/Aimer-zero/wuyun/main/install.sh | bash -s -- --target codex
```

重启/刷新 AI Agent 后，直接复制一个提示词：

```text
使用 $wuyun，mode code-audit。
目标：当前本地仓库。
请先被动理解架构和信任边界，再列出攻击面、生成漏洞假设，最后只报告有证据的 confirmed/likely/speculative 结果和修复建议。
```

更新时重新运行安装命令即可。只安装到 Claude：

```bash
curl -fsSL https://raw.githubusercontent.com/Aimer-zero/wuyun/main/install.sh | bash -s -- --target claude
```

本地开发安装当前 checkout：

```bash
./install.sh --source-dir . --target codex
```

## 为什么值得使用

- **会路由**：`$wuyun` 根据任务自动选择 Web/API、云、JS 逆向、浏览器运行时、协议、认证、AI 安全、Recon、PoC 辅助等子 skill。
- **重证据**：输出区分 confirmed / likely / speculative / ruled-out，减少“扫描器式误报”。
- **低影响默认**：优先本地、被动、dry-run、canary marker、合成数据和 owner-assisted 验证。
- **可落地**：每个模块自带 references 和 scripts，能产出路线、wordlist、HAR 分析、OpenAPI 分析、JWT 离线审计、PoC 计划和报告模板。
- **可组合**：chain mode 能把 recon、JS、HAR、Web/API、auth、cloud 等结果合成下一步验证路线。

## 常用提示词

```text
使用 $wuyun，对 https://example.com 进行 Web/API 审计。低影响、低频率，只输出有证据的发现。
```

```text
使用 $wuyun，分析本地 /path/to/bundle.js，提取 API、WebSocket、GraphQL、签名逻辑和后续验证假设。
```

```text
使用 $wuyun，chain mode，聚合 recon.json、js-surface.json、har-analysis.json，推荐下一步 skill 和安全验证路线。
```

```text
使用 $wuyun-exploit-assist，把已确认的 SSTI/SQLi/反序列化线索整理成 canary-safe 最小 PoC 计划；不要生成 webshell、反弹 shell、数据导出或 WAF 绕过 payload。
```

更多可复制示例见 `examples/`。

## 模块

```text
wuyun/                    # 主 Skill：router、研究方法、chain mode、质量门禁
wuyun-web-api-audit/      # Web/API 审计：BOLA/IDOR、BFLA、注入、SSRF、上传、业务逻辑
wuyun-exploit-assist/     # Canary-safe PoC/reproducer 计划：SSTI、SQLi、反序列化、XXE/SSRF
wuyun-cloud-vuln/         # 云安全：SSRF、metadata、STS/CAM/IAM、对象存储
wuyun-js-reverse/         # 前端 JS 逆向：API 资产、签名逻辑、sourcemap、WebSocket/GraphQL
wuyun-js-deobfuscation/   # JS AST 反混淆：字符串数组、控制流、WASM、签名协议
wuyun-browser-runtime/    # 浏览器运行时：HAR/DevTools、Service Worker、CDN/WAF/风控归因
wuyun-protocol-analysis/  # 协议分析：WebSocket、GraphQL、SSE、JSON-RPC、gRPC/protobuf
wuyun-auth-audit/         # 认证授权：JWT、OAuth/OIDC、SAML、Session、Cookie、多租户权限
wuyun-ai-audit/           # AI 安全：LLM/RAG/Agent、提示注入、工具边界、输出 Sink
wuyun-recon/              # Recon：范围规划、dork、CT/subdomain、路由字典、工具导出
wuyun-evasion/            # 防御性检测健壮性：规范化差异、parser mismatch、origin exposure 计划
```

## 本地验证

```bash
python3 wuyun/scripts/validate_skill.py .
python3 wuyun/scripts/run_eval.py .
python3 wuyun/scripts/quality_gate.py . --skip-preflight
bash -n install.sh
```

常用 CLI：

```bash
python3 wuyun/scripts/wuyun_cli.py playbooks
python3 wuyun/scripts/wuyun_cli.py eval .
python3 wuyun/scripts/wuyun_cli.py audit /path/to/repo --code-only
python3 wuyun/scripts/wuyun_cli.py js-reverse /path/to/dist --json
python3 wuyun/scripts/wuyun_cli.py chain recon.json js-surface.json har-analysis.json
python3 wuyun/scripts/wuyun_cli.py cloudflare -- --har capture.har
python3 wuyun/scripts/wuyun_cli.py ssti-probes --engine all
```

## 适用场景

- 本地源码 / 配置安全审计
- Web / API 在线安全测试和生产安全复核
- 前端 JS 逆向、反混淆、签名协议分析
- 浏览器运行时复现、HAR 证据分析
- 跨模块发现聚合、chain mode 下一步路线规划
- WAF/CDN/AI 策略的防御性检测健壮性评估
- JWT / OAuth / SAML / 多租户权限专项
- LLM / RAG / Agent 安全评估
- 云安全分析、SSRF、临时凭证影响判断
- CTF / 靶场 / 实验环境
- 已确认线索的 canary-safe PoC/reproducer 计划

## 不适用场景

- 违法、违规或超出授权范围的测试
- 公网批量扫描、大规模探测、高频 fuzz
- 未经授权的主动 payload 投递或业务数据访问
- Webshell、反弹 shell、持久化、恶意程序、破坏性 payload
- WAF 绕过 payload 包、请求指纹伪装、CAPTCHA 自动化、代理轮换、AI 内容过滤绕过变体库
- 获取、保留或输出无关用户数据、密钥、Token、数据库内容

## License

MIT License. See [LICENSE](LICENSE).

---

# English

> [中文](#wuyun--乌云) | English

Wuyun is a vulnerability-research skill suite for AI coding agents. It turns “security review” into reusable workflows: understand the system, map attack surface, form hypotheses, validate with low impact, and report remediation-focused findings.

Its goal is to make Codex/Claude behave more like a careful researcher than a scanner for **authorized assessments, CTF/lab work, local code audits, and defensive security reviews**.

## 60-second quick start

```bash
curl -fsSL https://raw.githubusercontent.com/Aimer-zero/wuyun/main/install.sh | bash -s -- --target codex
```

Restart/reload your AI agent, then paste:

```text
Use $wuyun, mode code-audit.
Target: the current local repository.
Please passively understand architecture and trust boundaries first, then map attack surface, generate vulnerability hypotheses, and report only confirmed/likely/speculative findings with evidence and remediation.
```

Rerun the installer to update. Install only for Claude:

```bash
curl -fsSL https://raw.githubusercontent.com/Aimer-zero/wuyun/main/install.sh | bash -s -- --target claude
```

Install from a local checkout:

```bash
./install.sh --source-dir . --target codex
```

## Why use it

- **Routing**: `$wuyun` selects the right companion skill for Web/API, cloud, JS reverse, browser runtime, protocol, auth, AI security, recon, and PoC assistance.
- **Evidence-first**: outputs separate confirmed / likely / speculative / ruled-out items to reduce scanner-style false positives.
- **Low-impact by default**: prefers local/passive/dry-run workflows, canary markers, synthetic data, and owner-assisted validation.
- **Practical**: bundled references and scripts produce plans, wordlists, HAR analysis, OpenAPI review, JWT offline audit, PoC plans, and report templates.
- **Composable**: chain mode combines recon, JS, HAR, Web/API, auth, and cloud outputs into the next safe validation path.

## Copy-paste prompts

```text
Use $wuyun to audit https://example.com for Web/API vulnerabilities. Keep testing low-impact and low-rate; report only evidence-backed findings.
```

```text
Use $wuyun to analyze /path/to/bundle.js and extract APIs, WebSockets, GraphQL, signing logic, and follow-up validation hypotheses.
```

```text
Use $wuyun, chain mode, to combine recon.json, js-surface.json, and har-analysis.json into next-skill recommendations and safe validation steps.
```

```text
Use $wuyun-exploit-assist to turn a confirmed SSTI/SQLi/deserialization lead into a canary-safe minimal PoC plan; do not generate webshells, reverse shells, data-dumping, or WAF-bypass payloads.
```

More examples live in `examples/`.

## Modules

```text
wuyun/                    # Main skill: router, research method, chain mode, quality gates
wuyun-web-api-audit/      # Web/API audit: BOLA/IDOR, BFLA, injection, SSRF, upload, business logic
wuyun-exploit-assist/     # Canary-safe PoC/reproducer planning: SSTI, SQLi, deserialization, XXE/SSRF
wuyun-cloud-vuln/         # Cloud security: SSRF, metadata, STS/CAM/IAM, object storage
wuyun-js-reverse/         # Frontend JS reverse: API assets, signatures, sourcemaps, WebSocket/GraphQL
wuyun-js-deobfuscation/   # JS AST deobfuscation: string arrays, control flow, WASM, signing protocols
wuyun-browser-runtime/    # Browser runtime: HAR/DevTools, Service Worker, CDN/WAF/risk-control attribution
wuyun-protocol-analysis/  # Protocol analysis: WebSocket, GraphQL, SSE, JSON-RPC, gRPC/protobuf
wuyun-auth-audit/         # Auth: JWT, OAuth/OIDC, SAML, session, cookie, tenant authorization
wuyun-ai-audit/           # AI security: LLM/RAG/Agent, prompt injection, tool boundaries, output sinks
wuyun-recon/              # Recon: scoped plans, dorks, CT/subdomains, route wordlists, tool artifacts
wuyun-evasion/            # Defensive detection resilience: canonicalization, parser mismatch, origin exposure plans
```

## Local validation

```bash
python3 wuyun/scripts/validate_skill.py .
python3 wuyun/scripts/run_eval.py .
python3 wuyun/scripts/quality_gate.py . --skip-preflight
bash -n install.sh
```

Useful CLI commands:

```bash
python3 wuyun/scripts/wuyun_cli.py playbooks
python3 wuyun/scripts/wuyun_cli.py eval .
python3 wuyun/scripts/wuyun_cli.py audit /path/to/repo --code-only
python3 wuyun/scripts/wuyun_cli.py js-reverse /path/to/dist --json
python3 wuyun/scripts/wuyun_cli.py chain recon.json js-surface.json har-analysis.json
python3 wuyun/scripts/wuyun_cli.py cloudflare -- --har capture.har
python3 wuyun/scripts/wuyun_cli.py ssti-probes --engine all
```

## Intended use

- Local source/config security review
- Online Web/API testing and production-safe review
- Frontend JS reverse engineering, deobfuscation, and signing protocol analysis
- Browser runtime reproduction and HAR evidence analysis
- Cross-module finding synthesis and chain-mode next-step planning
- Defensive WAF/CDN/AI-policy detection-resilience assessment
- JWT/OAuth/SAML/session/tenant authorization review
- LLM/RAG/agent security assessment
- Cloud security analysis, SSRF, and temporary credential impact triage
- CTF/lab/sandbox research
- Canary-safe PoC/reproducer planning for identified leads

## Not intended for

- Illegal, abusive, or out-of-scope testing
- Internet-wide scanning, mass probing, or high-volume fuzzing
- Unauthorized active payload delivery or business-data access
- Webshells, reverse shells, persistence, malware, or destructive payloads
- WAF-bypass payload packs, request fingerprint spoofing, CAPTCHA automation, proxy rotation, or AI filter bypass variants
- Collecting, retaining, or outputting unrelated user data, secrets, tokens, or database contents

## License

MIT License. See [LICENSE](LICENSE).
