# Wuyun / 乌云

> 中文 | [English](#english)

Wuyun 是一个面向 AI 编码助手的漏洞研究 Skill，帮助安全研究人员完成代码审计、Web/API 审计、云安全分析和 CTF/Lab 调研。

只需调用 `$wuyun`，AI 会根据任务自动选择合适的子模块。

## 安装

```bash
curl -fsSL https://raw.githubusercontent.com/Aimer-zero/wuyun/main/install.sh | bash
```

安装后重启 AI Agent。更新时重新执行上面的命令即可。

只安装到某个平台：

```bash
curl -fsSL https://raw.githubusercontent.com/Aimer-zero/wuyun/main/install.sh | bash -s -- --target codex
curl -fsSL https://raw.githubusercontent.com/Aimer-zero/wuyun/main/install.sh | bash -s -- --target claude
```

## 使用

直接告诉 AI 你要做什么，Skill Router 会自动路由到对应模块：

```text
使用 $wuyun，对 https://example.com 进行 Web/API 审计。
```

```text
使用 $wuyun，分析本地 /path/to/bundle.js，提取 API 和签名逻辑。
```

```text
使用 $wuyun，审计本地仓库 /path/to/repo 的源码安全。
```

```text
使用 $wuyun，分析 capture.har，识别 CDN/WAF 行为和协议结构。
```

```text
使用 $wuyun，对 JWT eyJ... 做离线风险分析。
```

```text
使用 $wuyun，CTF/Lab 模式，目标是我提供的题目文件。
```

## 模块

```text
wuyun/                    # 主 Skill，包含 Skill Router
wuyun-web-api-audit/      # Web/API 审计
wuyun-cloud-vuln/         # 云安全 / SSRF / 临时凭证
wuyun-js-reverse/         # 前端 JS 逆向 / API 资产提取
wuyun-js-deobfuscation/   # JS AST 反混淆 / 签名协议 / WASM
wuyun-browser-runtime/    # 浏览器运行时 / HAR / 风控行为归因
wuyun-protocol-analysis/  # WebSocket / GraphQL / gRPC / 协议分析
wuyun-auth-audit/         # JWT / OAuth / SAML / Session / 多租户权限
wuyun-ai-audit/           # LLM / RAG / Agent / 提示注入
wuyun-recon/              # 侦察计划 / 路由字典 / 工具链导出
wuyun-evasion/            # 规范化差异 / 源站暴露分析
```

## 适用场景

- 本地源码 / 配置安全审计
- Web / API 在线安全测试
- 前端 JS 逆向、反混淆、签名协议分析
- 浏览器运行时复现、HAR 证据分析
- JWT / OAuth / SAML / 多租户权限专项
- LLM / RAG / Agent 安全评估
- 云安全分析、SSRF、临时凭证
- CTF / 靶场 / 实验环境

## 不适用场景

- 违法、违规或超出授权范围的测试
- 公网批量扫描、大规模探测
- 未经授权的主动 fuzz / payload 投递
- 获取或保留真实用户数据、密钥、Token
- 部署恶意程序、造成业务中断

## 免责声明

本项目面向**合法合规的安全研究、代码审计、CTF/Lab 和防御性安全工作**。使用者须自行确认授权范围，并对自己的行为负责。

## License

MIT License. See [LICENSE](LICENSE).

---

# English

> [中文](#wuyun--乌云) | English

Wuyun is a vulnerability research Skill for AI coding agents. Use `$wuyun` and describe your task — the built-in Skill Router automatically loads the right companion workflow.

## Installation

```bash
curl -fsSL https://raw.githubusercontent.com/Aimer-zero/wuyun/main/install.sh | bash
```

Restart your AI agent after installation. Rerun the same command to update.

Install for one platform only:

```bash
curl -fsSL https://raw.githubusercontent.com/Aimer-zero/wuyun/main/install.sh | bash -s -- --target codex
curl -fsSL https://raw.githubusercontent.com/Aimer-zero/wuyun/main/install.sh | bash -s -- --target claude
```

## Usage

Just describe your task. The Skill Router picks the right module automatically:

```text
Use $wuyun to audit https://example.com for Web/API vulnerabilities.
```

```text
Use $wuyun to analyze /path/to/bundle.js and extract APIs and signing logic.
```

```text
Use $wuyun to review the local repository /path/to/repo for security issues.
```

```text
Use $wuyun to analyze capture.har and identify CDN/WAF behavior and protocol structure.
```

```text
Use $wuyun to triage JWT eyJ... offline for structural risks.
```

```text
Use $wuyun, CTF/Lab mode, target is the challenge files I provide.
```

## Modules

```text
wuyun/                    # Main Skill with Skill Router
wuyun-web-api-audit/      # Web/API audit
wuyun-cloud-vuln/         # Cloud security / SSRF / temporary credentials
wuyun-js-reverse/         # Frontend JS reverse / API surface extraction
wuyun-js-deobfuscation/   # JS AST deobfuscation / signatures / WASM
wuyun-browser-runtime/    # Browser runtime / HAR / risk-control attribution
wuyun-protocol-analysis/  # WebSocket / GraphQL / gRPC / protocol analysis
wuyun-auth-audit/         # JWT / OAuth / SAML / session / tenant authorization
wuyun-ai-audit/           # LLM / RAG / agent / prompt injection
wuyun-recon/              # Recon plans / route wordlists / tool artifacts
wuyun-evasion/            # Canonicalization / origin exposure analysis
```

## Intended Use

- Local source / config security review
- Online Web / API security testing
- Frontend JS reverse engineering, deobfuscation, signing protocol analysis
- Browser runtime reproduction, HAR evidence analysis
- JWT / OAuth / SAML / tenant authorization review
- LLM / RAG / agent security assessment
- Cloud security analysis, SSRF, temporary credentials
- CTF / lab / sandbox research

## Not Intended For

- Illegal, abusive, or out-of-scope testing
- Internet-wide scanning or mass probing
- Active fuzzing or payload delivery without authorization
- Collecting or retaining real user data, secrets, or tokens
- Deploying malware or causing service disruption

## Disclaimer

This project is intended for **lawful security research, code auditing, CTF/Lab work, and defensive security activities**. You are responsible for determining your authorization scope and your own actions.

## License

MIT License. See [LICENSE](LICENSE).
